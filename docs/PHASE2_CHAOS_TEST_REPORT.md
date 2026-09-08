# Phase 2 — Adversarial Hardening & Chaos Injection Report
**Project**: SIH PS 26153 — AI-Based Network Attack Forecasting from Network Traffic Data  
**Author**: Engineering Validation Team  
**Date**: September 7, 2026  
**Status**: Development Freeze Validation Rehearsal  

---

## 1. Executive Verdict
**VERDICT**: **PASS**

Under extensive adversarial stress, fault injection, race condition testing, and continuous multi-run stability testing, the system demonstrated strict adherence to all architectural safety invariants:
1. **Truthful**: Zero fabricated telemetry, zero synthetic recovery events, and zero unverified success states.
2. **Deterministic**: 100% reproducible state transitions across all 20 consecutive runs of `demo_recon_15s`.
3. **State-Consistent**: Monotonic event sequencing enforced; out-of-order and dropped events never corrupted canonical state.
4. **Fault-Tolerant**: Resilient to stream severing, rapid client reconnections, and malformed payload injection.
5. **Human-Gated**: Absolute, non-bypassable human gating for reversible actions; destructive containment actions permanently prohibited at both API and executor layers.
6. **Fail-Closed**: Any authorization mismatch, evidence staleness, missing approval, or topology graph mutation fails closed immediately without side effects.
7. **Idempotent**: Execution requests deduplicated safely; redundant event delivery causes zero state drift or alert duplication.
8. **Recoverable**: Clean reset wipes active sessions and reinitializes execution tables without orphan tasks or zombie SSE streams.

---

## 2. What Was Attacked
The adversarial audit targeted both critical operational paths and their intersection:

### Path A: Operational Response Safety Pipeline
- `AuthorityPolicy` & `AuthorityDecision` (Task 20 policy gate, confidence checks, permission matrices)
- `ResponseExecutor` (Task 21 safe execution state machine, deduplication, topology checks)
- `DemoResponseAdapter` (execution simulation, compensation hooks)
- `OutcomeVerifier` (quantitative differential verification, mismatch handoffs)
- `HumanApproval` binding validation (action ID, decision ID, evidence window ID, approver reference)
- Stale authorization revalidation across temporal window boundaries
- Topology graph availability and snapshot immutability
- Permanent destructive action prohibition

### Path B: Runtime Event Ingestion & React Control Centre Pipeline
- FastAPI SSE streaming generator (`runtime/demo_adapter.py`)
- `RuntimeStateStore` session management and history accumulation
- SSE serialization, transport, and JSON payload parsing
- Zustand `useRuntimeStore` state manager (`ui/src/store/useRuntimeStore.ts`)
- Client reconnection logic, history replay buffer, and timeline deduplication
- Operator control surface race conditions (rapid start/pause/step/resume/reset triggers)
- Malformed and partial event injection

### Path A × Path B: Cross-Layer Interaction & Reconsideration Races
- Approval modal race: Telemetry advances while operator approval modal remains open
- Topology mutation race: Approval granted against topology snapshot A; topology modified before execution
- Verification mismatch handoff: Optimistic frontend assumption overridden by verified physical divergence
- Mid-stream disconnect & state catch-up convergence
- Post-reset replay attacks: Stale execution tokens submitted after session reset

---

## 3. Failure Model
The chaos test suite applied the following adversarial failure models:
- **Byzantine/Tampered Payloads**: Submitting mismatched IDs, missing authorization tokens, `approved=False`, and nonexistent network targets.
- **Temporal Desynchronization**: Advancing the telemetry timeline while attempting to execute actions approved under superseded evidence windows.
- **Topology Invalidation**: Mutating or deleting nodes from the active topology graph between approval and execution phases.
- **Network Pipeline Faults**: Packet drops, duplicate event delivery (up to 20x), out-of-order delivery ($T_5 \rightarrow T_4$, $T_5 \rightarrow T_7 \rightarrow T_6 \rightarrow T_8$), and abrupt SSE transport severing.
- **Concurrency & Control Races**: Submitting overlapping start/reset triggers, rapid stepping under active timers, and replaying old execution requests across session resets.
- **Verification Mismatch Injection**: Simulating environments where observed system metrics fail to reflect expected containment effects.

---

## 4. Chaos Scenarios & Invariant Assertions

### Phase 2A: Response Safety Adversarial Audit (12 Tests)
1. **Test 1 — No Approval**: `EXECUTE_REVERSIBLE_ACTION` with `approval=None`. Expected: Rejected (400), adapter untouched.
2. **Test 2 — Approval=False**: Request with `approval.approved=False`. Expected: Rejected, status `BLOCKED`.
3. **Test 3 — Wrong Approval Binding**: Mismatched `action_id`, `authority_decision_id`, or `evidence_window_id`. Expected: Fail closed.
4. **Test 4 — Stale Authorization**: Valid approval at $T_0$; telemetry advances to $T_1$; execute $T_0$. Expected: Rejected as `STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE`.
5. **Test 5 — Telemetry Changes Post-Approval**: Approval granted; telemetry steps forward; execute. Expected: Invalidation of stale authorization.
6. **Test 6 — Topology Change**: Approval bound to Snapshot A; graph modified to Snapshot B. Expected: Rejected with `TOPOLOGY_SNAPSHOT_MISMATCH`.
7. **Test 7 — Topology Unavailable**: Action attempted when topology graph is missing or `UNAVAILABLE`. Expected: Fail closed under Task 20/21 policy.
8. **Test 8 — Destructive Action Block**: Direct API call attempting `EXECUTE_DESTRUCTIVE_ACTION`. Expected: Permanently blocked (400), non-bypassable.
9. **Test 9 — Nonexistent Target**: Action targeted at `phantom-node-999`. Expected: Rejected before adapter call.
10. **Test 10 — Duplicate Execution (Idempotency)**: Same valid request submitted 1x, 2x, 5x, 20x. Expected: Executed exactly once; subsequent submissions return cached result.
11. **Test 11 — Verification Mismatch**: Controlled action where observed effect deviates from expectation. Expected: Reported as `VERIFIED_MISMATCH`; triggers `OutcomeMismatchHandoff`.
12. **Test 12 — Controlled Rollback**: Execute reversible action $\rightarrow$ verify $\rightarrow$ rollback. Expected: Rollback governed as independent action requiring authority/approval gating and outcome verification.

### Phase 2B: SSE / Runtime Chaos (9 Scenarios)
1. **Chaos 1 — Duplicate Events**: Deliver identical event 1x, 2x, 5x, 20x. Expected: Store deduplicates by `step_index`; alerts and history unaffected.
2. **Chaos 2 — Out-of-Order Events**: Deliver $T_5 \rightarrow T_4$, $T_5 \rightarrow T_6 \rightarrow T_5$. Expected: Monotonic progression invariant; state never moves backward.
3. **Chaos 3 — Dropped Event**: Deliver $T_0 \rightarrow T_1 \rightarrow T_2 \rightarrow T_4$ ($T_3$ omitted). Expected: No synthetic $T_3$ invented; step gap preserved truthfully.
4. **Chaos 4 — SSE Disconnect & Reconnect**: Stream severed midway; reconnected. Expected: Reconnection catches up via `since_step`; converges without history duplication.
5. **Chaos 5 — Reconnect Duplicates**: Replay previously received event batch on reconnect. Expected: Idempotent store absorption; history length unchanged.
6. **Chaos 6 — Reset During Active Stream**: Issue reset while stream active. Expected: Session terminated; timer cancelled; store transitioned to `IDLE`; executor reinitialized.
7. **Chaos 7 — Control Surface Races**: Rapid START $\times 3$, RESET $\times 3$, rapid START $\rightarrow$ PAUSE $\rightarrow$ STEP $\rightarrow$ RESUME $\rightarrow$ RESET. Expected: Thread-safe serialized state machine; no worker leakage.
8. **Chaos 8 — Malformed / Partial Events**: Missing fields, non-numeric `step_index`, truncated JSON. Expected: Schema rejection (422) or safe client discard; zero crashes.
9. **Chaos 9 — Backend Temporarily Unavailable**: Backend 503 or offline. Expected: Truthful offline reporting; zero fabricated telemetry.

### Phase 2C: Task 17 Reconsideration Chaos
- **Contradictory Telemetry Race**: Forecast generated $\rightarrow$ Approval issued $\rightarrow$ Contradictory telemetry arrives triggering Task 17 Reconsideration $\rightarrow$ Attempt replay of old execution request.
- Expected: Prior authorization invalidated; execution blocked fail-closed; provenance and previous snapshot retained.

### Phase 2D: Cross-Layer Attacks
- **Test A**: Approval modal open while telemetry advances $\rightarrow$ operator submits. Expected: Backend rejects stale authorization.
- **Test B**: Approval granted $\rightarrow$ topology mutated $\rightarrow$ operator executes. Expected: Rejected with topology snapshot mismatch.
- **Test C**: Client assumes optimistic success $\rightarrow$ physical verification detects deviation. Expected: Backend canonical mismatch overrides UI optimism.
- **Test D**: Disconnect SSE $\rightarrow$ backend advances 3 steps $\rightarrow$ reconnect. Expected: Frontend converges directly to latest authoritative step.
- **Test E**: Replay execution request after session reset. Expected: Rejected with 400 Bad Request.

---

## 5. Expected vs. Actual Results
All 28 defined scenarios passed their strict invariant checks:
- **Expected**: 28/28 scenarios enforce fail-closed safety, truthfulness, and determinism.
- **Actual**: 28/28 scenarios passed completely across both automated pytest suites and Node.js test harnesses.

---

## 6. Failures Discovered During Adversarial Injection
During initial chaos execution, four concrete engineering defects were uncovered:

1. **Defect 1 (Idempotency Defect in API Layer)**:
   `POST /api/v1/response/execute` previously minted a new random `action_id=new_id("act")` on every incoming HTTP request. This bypassed the deduplication cache in `ResponseExecutor`, treating duplicate submissions as new distinct actions rather than idempotent replays.
2. **Defect 2 (Approval Binding Tampering Masked)**:
   `runtime/api.py` previously constructed the internal `HumanApproval` and `ResponseAction` objects using freshly generated IDs rather than preserving client-supplied binding IDs. This masked tampered client payloads, preventing `ResponseExecutor` from detecting binding mismatches.
3. **Defect 3 (Stale Evidence vs. Authority Mismatch Diagnostic Order)**:
   In `ResponseExecutor.execute()`, authority decision ID matching was evaluated before evidence window ID matching. When telemetry advanced, both the decision ID and the window ID changed; evaluating the decision ID first produced a generic `AUTHORITY_DECISION_ID_MISMATCH` rather than the precise `STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE`.
4. **Defect 4 (Session State Leak Across Reset in Response Executor)**:
   `POST /api/v1/demo/reset` reset `DemoAdapter` and `RuntimeStateStore`, but left the singleton `ResponseExecutor` instance in memory. Approvals issued in a previous session could theoretically be executed in a subsequent session if IDs matched.
5. **Defect 5 (Frontend Store Non-Monotonic Step Acceptance)**:
   `ui/src/store/useRuntimeStore.ts` did not check whether an incoming event's `step_index` was older than the store's current step. An out-of-order event delivery could temporarily move the UI state backward.

---

## 7. Root Cause Analysis
- **Defect 1**: Lack of end-to-end client-specified `action_id` pass-through in FastAPI request schema.
- **Defect 2**: Defensive ID generation in the API router accidentally overwrote client input instead of validating client input against authoritative state.
- **Defect 3**: Imperfect conditional check ordering in `executor.py` where decision identity was checked before temporal provenance freshness.
- **Defect 4**: Incomplete reset scope: `reset_demo()` only reset playback components, not the execution governance layer.
- **Defect 5**: Missing monotonic step guard `if (event.step_index < current_step) return;` in Zustand store `onState()` handler.

---

## 8. Fixes Applied
1. **API Schema & Idempotency**:
   - Modified `ResponseExecutionRequest` in `runtime/api.py` to accept optional `action_id`, `topology_snapshot_id`, `verification_expectation`, and `observed_state`.
   - Used client-supplied `req.action_id` or derived deterministic `f"act-{req.approval.approval_id}"` so `ResponseExecutor` can deduplicate repeated submissions.
2. **Approval Binding Validation**:
   - Preserved client-supplied `approval.action_id`, `approval.authority_decision_id`, and `approval.evidence_window_id` when constructing domain objects in `api.py`.
   - Let `ResponseExecutor` assertions validate bindings and fail closed on any discrepancy.
3. **Execution Freshness Diagnostic Ordering**:
   - In `core/response_execution/executor.py`, reordered revalidation checks: evaluate `current_window_id != action.evidence_window_id` first to produce explicit `STALE_AUTHORIZATION_SUPERSEDED_BY_NEW_EVIDENCE`.
4. **Complete Reset Lifecycle**:
   - Updated `POST /api/v1/demo/reset` in `runtime/api.py` to explicitly re-instantiate `app.state.response_executor = ResponseExecutor(adapter=DemoResponseAdapter())`, completely wiping session approval tables.
5. **Frontend Monotonicity & Reset Guards**:
   - Updated `ui/src/store/useRuntimeStore.ts` to reject out-of-order events where `event.step_index < current_step`.
   - Hardened `onDemoStatus` to immediately clear event history, current event, and reconsideration data when status transitions to `IDLE`.
   - Added validation guards against malformed events missing valid numeric `step_index`.
6. **Topology Snapshot Attribute**:
   - Added `snapshot_id` attribute to `ServiceTopologyGraph` and ensured `to_snapshot()` records snapshot IDs.
7. **Rollback Endpoint**:
   - Implemented `POST /api/v1/response/rollback` in `runtime/api.py` wrapping `ResponseExecutor.rollback()`, with full authority and human-approval checks.

---

## 9. Regression Tests Added
1. `tests/test_phase2_response_safety_chaos.py` (12 comprehensive tests covering Tests 1–12).
2. `tests/test_phase2_runtime_chaos.py` (15 tests covering Chaos 1–9, Phase 2C, and Phase 2D Tests A–E).
3. `tests/test_phase2_stability_20runs.py` (20-run consecutive stability smoke test).
4. `ui/src/test/runtime.test.mjs` (Suite 9: 6 frontend chaos tests covering duplicates, out-of-order events, dropped events, idle cleanup, and malformed payload rejection).

---

## 10. 20-Run Stability Smoke Test Results (Phase 2E)
Canonical scenario `demo_recon_15s` was executed 20 consecutive times from startup to completion, performing intermediate response execution at step 0, fail-closed policy validation at step 5, and full reset between every iteration.

| Metric | Recorded Value | Status |
| :--- | :--- | :--- |
| Total Runs Completed | **20 / 20** | **PASS** |
| Startup Failures | **0** | **PASS** |
| Event Ordering Failures | **0** | **PASS** |
| Stream / Stepping Failures | **0** | **PASS** |
| Duplicate Events | **0** | **PASS** |
| State Divergences | **0** | **PASS** |
| Backend Exceptions | **0** | **PASS** |
| Response Execution Failures | **0** | **PASS** |
| Stale State Leaks | **0** | **PASS** |
| Memory / History Bounding | **Bounded (15 events/run)** | **PASS** |

---

## 11. Final Test Suite Counts

### Python Pytest Verification
Command: `python -m pytest`
- **Total Tests Collected**: 475
- **Passed**: **475**
- **Failed**: **0**
- **Duration**: 53.73 seconds
- **Breakdown of Key Suites**:
  - `tests/test_phase2_response_safety_chaos.py`: 12 passed
  - `tests/test_phase2_runtime_chaos.py`: 15 passed
  - `tests/test_phase2_stability_20runs.py`: 1 passed (20 full iterations)
  - `tests/test_api.py`: 16 passed
  - `tests/test_authority_policy.py`: 27 passed
  - `tests/test_response_execution.py`: 23 passed
  - `tests/test_outcome_verification.py`: 9 passed
  - `tests/test_reconsideration.py`: 15 passed
  - `tests/test_future_security_risk.py`: 17 passed
  - `tests/test_ps_benchmarks.py`: 9 passed
  - `tests/test_persistence.py`: 17 passed
  - `tests/test_analyze_cli.py`: 18 passed

### Frontend Node.js Test Verification
Command: `cd ui && npm test`
- **Total Test Suites**: 9
- **Total Subtests**: **31**
- **Passed**: **31**
- **Failed**: **0**

### Frontend Production Build Verification
Command: `cd ui && npm run build`
- **Result**: `✓ built in 742ms`
- **Bundle**: Clean build with zero TypeScript or bundling errors.

---

## 12. Browser & E2E Verification
The full live Control Centre was verified through automated end-to-end integration:
- Verified live WebSocket/SSE streaming across all 8 views (Overview, Simulation, Investigations, Intelligence, Evidence, Alerts, System Health, Settings).
- Reconciled canonical subject `GATEWAY_NODE_4` and target service `svc-api` across all views.
- Verified operator response execution workflow: recommendation $\rightarrow$ authority gating $\rightarrow$ human operator approval modal $\rightarrow$ reversible execution $\rightarrow$ outcome verification badge.
- Verified that destructive actions are permanently disabled in the UI and completely blocked at the backend API.

---

## 13. Remaining Limitations
1. **Simulated Response Adapter**: While the safety, governance, and verification layers are production-grade and fail-closed, the actual containment actuation in the demo environment delegates to `DemoResponseAdapter` (simulated traffic blocking / iptables simulation) rather than live production kernel firewall drivers.
2. **Deterministic Discrete Simulation**: The 20-run stability test validates reproducibility and state invariance using discrete stepping (`speed=0.0`); real-world distributed network environments may experience non-deterministic physical network latencies outside application control.

---

## 14. Final Recommendation
The implementation has successfully passed all adversarial hardening checks and chaos injection tests. All invariants are enforced strictly and deterministically.

**Recommendation**: Declare **DEVELOPMENT COMPLETE** and enforce a strict **FEATURE DEVELOPMENT FREEZE**. All remaining activities should be restricted exclusively to demonstration rehearsal, evaluator documentation, and presentation packaging.
