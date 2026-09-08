"""Phase 2E — 20-Run Stability Test Harness (SIH PS 26153).

Executes canonical scenario demo_recon_15s at least 20 consecutive times against
the runtime API and state store, recording:
- startup failures
- event ordering failures
- stream/stepping failures
- duplicate events
- state divergence
- backend exceptions
- response execution integrity
- stale state leaks
- memory/history bounding
"""

import pytest
from fastapi.testclient import TestClient
from runtime.api import app


class TestPhase2TwentyRunStability:
    """20-run stability smoke test for demo_recon_15s."""

    def test_twenty_consecutive_runs_demo_recon_15s(self):
        client = TestClient(app)
        num_runs = 20

        # Metrics aggregation
        metrics = {
            "startup_failures": 0,
            "event_ordering_failures": 0,
            "stream_failures": 0,
            "duplicate_events": 0,
            "state_divergence": 0,
            "backend_exceptions": 0,
            "response_execution_failures": 0,
            "stale_state_leaks": 0,
            "total_runs_completed": 0,
        }

        for run_idx in range(1, num_runs + 1):
            # 1. Clean reset before each run
            reset_resp = client.post("/api/v1/demo/reset")
            if reset_resp.status_code != 200:
                metrics["backend_exceptions"] += 1
                continue

            # Verify store is completely clean (no stale state leaks)
            status_before = client.get("/api/v1/demo/status").json()
            state_before = client.get("/api/v1/state/current").json()
            if status_before["status"] != "IDLE" or state_before["has_event"] is True:
                metrics["stale_state_leaks"] += 1

            # 2. Start demo_recon_15s with speed=0.0 for deterministic discrete stepping
            start_resp = client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
            if start_resp.status_code != 200:
                metrics["startup_failures"] += 1
                continue

            start_data = start_resp.json()
            total_steps = start_data.get("total_steps", 15)
            if total_steps <= 0:
                metrics["startup_failures"] += 1
                continue

            # 3. Step through entire scenario
            seen_step_indices = []
            last_step = -1

            for step_num in range(total_steps):
                step_resp = client.post("/api/v1/demo/step")
                if step_resp.status_code != 200:
                    metrics["stream_failures"] += 1
                    break

                step_data = step_resp.json()
                if not step_data.get("has_event"):
                    metrics["stream_failures"] += 1
                    break

                current_step_idx = step_data.get("step_index")
                if current_step_idx is None:
                    metrics["stream_failures"] += 1
                    break

                # Check duplicate events
                if current_step_idx in seen_step_indices:
                    metrics["duplicate_events"] += 1

                # Check monotonic ordering
                if current_step_idx != last_step + 1:
                    metrics["event_ordering_failures"] += 1

                seen_step_indices.append(current_step_idx)
                last_step = current_step_idx

                # At step 0: Verify response execution succeeds when permitted by authority policy
                if current_step_idx == 0:
                    auth_policy = step_data.get("authority_policy") or {}
                    auth_id = auth_policy.get("decision_id")
                    window_id = step_data.get("event_id")
                    action_id = f"act-run{run_idx}-step0"

                    approval_payload = {
                        "approved": True,
                        "approver_reference": "sec-lead",
                        "approval_reason": f"Permitted isolation test for run {run_idx}",
                        "action_id": action_id,
                        "authority_decision_id": auth_id,
                        "evidence_window_id": window_id,
                    }
                    exec_resp = client.post("/api/v1/response/execute", json={
                        "action_type": "isolate_node",
                        "target_node_id": "svc-api",
                        "approval": approval_payload,
                        "action_id": action_id,
                        "authority_decision_id": auth_id,
                        "evidence_window_id": window_id,
                    })
                    if exec_resp.status_code != 200 or exec_resp.json().get("status") != "EXECUTED" or not exec_resp.json().get("is_verified"):
                        metrics["response_execution_failures"] += 1

                # At step 5: Verify fail-closed policy enforcement (policy blocks execution due to medium trust)
                if current_step_idx == 5:
                    mid_status = client.get("/api/v1/demo/status").json()
                    if mid_status["current_step"] != 5 or mid_status["status"] != "RUNNING":
                        metrics["state_divergence"] += 1

                    auth_policy = step_data.get("authority_policy") or {}
                    auth_id = auth_policy.get("decision_id")
                    window_id = step_data.get("event_id")
                    action_id = f"act-run{run_idx}-step5"

                    approval_payload = {
                        "approved": True,
                        "approver_reference": "sec-lead",
                        "approval_reason": f"Attempting execution when policy blocks execution",
                        "action_id": action_id,
                        "authority_decision_id": auth_id,
                        "evidence_window_id": window_id,
                    }
                    exec_resp = client.post("/api/v1/response/execute", json={
                        "action_type": "isolate_node",
                        "target_node_id": "svc-api",
                        "approval": approval_payload,
                        "action_id": action_id,
                        "authority_decision_id": auth_id,
                        "evidence_window_id": window_id,
                    })
                    # Expected to fail closed with status == "BLOCKED" because EXECUTE_REVERSIBLE_ACTION is blocked
                    if exec_resp.status_code != 200 or exec_resp.json().get("status") != "BLOCKED":
                        metrics["response_execution_failures"] += 1

            # 4. Verify completion
            status_resp = client.get("/api/v1/demo/status").json()
            if status_resp.get("status") != "COMPLETED":
                metrics["state_divergence"] += 1

            if len(seen_step_indices) != total_steps:
                metrics["stream_failures"] += 1

            # Check history bounding
            hist_len = status_resp.get("history_count", 0)
            if hist_len != total_steps:
                metrics["state_divergence"] += 1

            # 5. Clean reset
            client.post("/api/v1/demo/reset")
            post_reset_status = client.get("/api/v1/demo/status").json()
            post_reset_state = client.get("/api/v1/state/current").json()
            if post_reset_status["status"] != "IDLE" or post_reset_state["has_event"] is True:
                metrics["stale_state_leaks"] += 1

            metrics["total_runs_completed"] += 1

        print(f"\n--- 20-Run Stability Test Summary ---")
        for k, v in metrics.items():
            print(f"  {k}: {v}")

        # Assert strict invariants
        assert metrics["total_runs_completed"] == 20
        assert metrics["startup_failures"] == 0
        assert metrics["event_ordering_failures"] == 0
        assert metrics["stream_failures"] == 0
        assert metrics["duplicate_events"] == 0
        assert metrics["state_divergence"] == 0
        assert metrics["backend_exceptions"] == 0
        assert metrics["response_execution_failures"] == 0
        assert metrics["stale_state_leaks"] == 0
