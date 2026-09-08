"""Manual validation script exercising FastAPI runtime server endpoints."""
from __future__ import annotations

import json
from fastapi.testclient import TestClient

from runtime.api import app

client = TestClient(app)

print("=" * 70)
print("FASTAPI RUNTIME SERVER MANUAL VALIDATION")
print("=" * 70)

# 1. Health
r = client.get("/api/v1/health")
print(f"\n1. GET /api/v1/health -> {r.status_code}")
print(json.dumps(r.json(), indent=2))

# 2. Demo Status
r = client.get("/api/v1/demo/status")
print(f"\n2. GET /api/v1/demo/status -> {r.status_code}")
print(json.dumps(r.json(), indent=2))

# 3. Start Demo
r = client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
print(f"\n3. POST /api/v1/demo/start -> {r.status_code}")
print(json.dumps(r.json(), indent=2))

# 4. Current State (step 0)
r_step = client.post("/api/v1/demo/step")
print(f"\n4. POST /api/v1/demo/step -> {r_step.status_code}")

r_state = client.get("/api/v1/state/current")
print(f"\n5. GET /api/v1/state/current -> {r_state.status_code}")
state_data = r_state.json()
print(f"  Step: {state_data['step_index']}, Time: {state_data['logical_time']}, Stage: {state_data['primary_stage']}, Risk: {state_data['current_risk_score']}")
print(f"  Features: {state_data['features']}")

# 6. Forecast
r_fc = client.get("/api/v1/forecast/current")
print(f"\n6. GET /api/v1/forecast/current -> {r_fc.status_code}")
fc_data = r_fc.json()
print(f"  Model: {fc_data['model_name']}, Deltas: {fc_data['predicted_deltas_h1']}")

# 7. Security
r_sec = client.get("/api/v1/security/current")
print(f"\n7. GET /api/v1/security/current -> {r_sec.status_code}")
sec_data = r_sec.json()
print(f"  Stage: {sec_data['primary_stage']} (conf: {sec_data['stage_confidence']}), Active Sigs: {sec_data['active_signatures']}")

# 8. Decision
r_dec = client.get("/api/v1/decision/current")
print(f"\n8. GET /api/v1/decision/current -> {r_dec.status_code}")
dec_data = r_dec.json()
print(f"  Priority: {dec_data['priority_level']}, Strategy: {dec_data['recommended_strategy']}, Reversible: {dec_data['is_reversible']}, HumanReq: {dec_data['requires_human']}")

# 9. Events
r_evt = client.get("/api/v1/events")
print(f"\n9. GET /api/v1/events -> {r_evt.status_code}")
print(f"  Total count: {r_evt.json()['total_count']}")

# Reset
client.post("/api/v1/demo/reset")
print("\n[OK] Validation completed successfully.")
