# SIH 26153 — Master Implementation Plan & Engineering Roadmap

---

## Phase 1 — Forecasting Foundation

### Task 1: Real AR(5) Temporal Dynamics Engine
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `CRITICAL`
- **Dependencies:** None (Completed)
- **Scope & Subtasks:**
  - `[x]` Train authoritative AR(5) model on chronologically split CIC-IDS2018 flow telemetry.
  - `[x]` Validate directional accuracy against zero-change and AR(3) baselines (achieved 68.10% directional accuracy).
  - `[x]` Verify generalization across 4/4 held-out infiltration blocks.
  - `[x]` Implement artifact serialization, checksum verification, and runtime loader.
- **Demonstration / Acceptance Criteria:**
  - Automated test suite proves round-trip model equivalence and strict historical context enforcement ($p=5$, 6 consecutive states required).

---

### Task 2: Explainability & Feature Contribution Integration
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `HIGH`
- **Dependencies:** Task 1
- **Scope & Subtasks:**
  - `[x]` Integrate runtime feature-attribution module into the forecasting path.
  - `[x]` Map top contributing delta features to human-readable security indicators.
  - `[x]` Generate structured rationale strings linking telemetry trajectory to hypothesis.
- **Demonstration / Acceptance Criteria:**
  - Every generated forecast artifact emits non-empty feature attributions and explanatory context verified by `runtime/verify_explainability.py`.

---

## Phase 2 — Runtime Foundation

### Task 3: DemoAdapter Execution Controller
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `HIGH`
- **Dependencies:** Task 1, Task 2
- **Scope & Subtasks:**
  - `[x]` Build execution lifecycle manager exposing `START`, `PAUSE`, `RESUME`, `STEP`, `RESET`, and `SPEED`.
  - `[x]` Enforce thread-safe lockouts preventing invalid state transitions.
  - `[x]` Decouple pacing control from state generation logic.
- **Demonstration / Acceptance Criteria:**
  - Engine state transitions verified via unit tests; adapter controls session tick cadence deterministically.

---

### Task 4: RuntimeStateStore Single Source of Truth
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `HIGH`
- **Dependencies:** Task 3
- **Scope & Subtasks:**
  - `[x]` Implement in-memory, thread-safe state store holding current telemetry, forecast, risk, and events.
  - `[x]` Maintain bounded sliding event history and telemetry buffer.
  - `[x]` Enforce frozen data contract types on all store updates.
- **Demonstration / Acceptance Criteria:**
  - Store atomically reflects state updates and provides point-in-time snapshots to downstream consumers without mutation races.

---

### Task 5: FastAPI Runtime Control & State Endpoints
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `HIGH`
- **Dependencies:** Task 4
- **Scope & Subtasks:**
  - `[x]` Expose REST endpoints for execution controls (`/api/control/{action}`).
  - `[x]` Expose state query endpoints (`/api/snapshot`, `/api/history`, `/api/health`).
  - `[x]` Implement input validation and error handling matching contract schemas.
- **Demonstration / Acceptance Criteria:**
  - Automated API test suite (`manual_validate_api.py`) passes all endpoint validation tests with HTTP 200/400 compliance.

---

### Task 6: Server-Sent Events (SSE) Live Streaming
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `HIGH`
- **Dependencies:** Task 4, Task 5
- **Scope & Subtasks:**
  - `[x]` Build `/api/events` SSE streaming endpoint for reactive state push.
  - `[x]` Implement heartbeat ping mechanism to maintain long-lived connections.
  - `[x]` Handle graceful client disconnects without backend thread leakage.
- **Demonstration / Acceptance Criteria:**
  - Continuous event streaming verified with `test_sse.py` and `manual_validate_sse.py` under simulated client consumption.

---

### Task 7: React Frontend Runtime Integration & State Synchronization
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `HIGH`
- **Dependencies:** Task 5, Task 6
- **Scope & Subtasks:**
  - `[x]` Implement frontend SSE listener (`sse.ts`) and API client (`api.ts`).
  - `[x]` Connect global Zustand/React state store to backend `RuntimeSnapshot`.
  - `[x]` Integrate global Command Palette and connection status indicators.
- **Demonstration / Acceptance Criteria:**
  - UI updates in real-time on SSE ticks with zero client polling; reconnection and error states reflect backend availability cleanly.

---

## Phase 3 — Operational Control Centre

### Task 8: Live Overview Operator Dashboard
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `HIGH`
- **Dependencies:** Task 7
- **Scope & Subtasks:**
  - `[x]` Display observed telemetry, AR(5) forecast trajectory, future security risk, and trust metrics.
  - `[x]` Render MITRE ATT&CK stage progression, signature indicators, and recommended response.
  - `[x]` Embed explainability summary showing dominant feature contributions.
- **Demonstration / Acceptance Criteria:**
  - Overview page functions as a cohesive operator summary dynamically driven by backend SSE state.

---

### Task 9: Live Simulation Operator Control Surface
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `HIGH`
- **Dependencies:** Task 3, Task 7
- **Scope & Subtasks:**
  - `[x]` Transform Simulation page into the dedicated experiment controller.
  - `[x]` Expose active controls: `START`, `PAUSE`, `RESUME`, `STEP`, `RESET`, and playback speed multipliers (0.5x, 1x, 2x, 5x).
  - `[x]` Display real-time experiment metadata: scenario profile, engine status, execution tick rate, and command log.
  - `[x]` Render live network trajectory graph with overlay of forward AR(5) forecast cones.
  - `[x]` Enforce architectural boundary: UI controls experiment pacing via `DemoAdapter`, but does not supply or manipulate future network states.
- **Demonstration / Acceptance Criteria:**
  - Operator controls experiment playback interactively; engine state transitions, command logs, and telemetry trajectories reflect accurately without UI-side mock generation. Verified end-to-end in browser.

---

### Task 10: Live Alerts & Escalation Workflow
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `HIGH`
- **Dependencies:** Task 4, Task 7
- **Scope & Subtasks:**
  - `[x]` Connect alerts directly to backend risk events rather than static thresholds.
  - `[x]` Structure alerts to show: observed behaviour $\to$ forecast trajectory $\to$ security interpretation $\to$ confidence/uncertainty $\to$ priority $\to$ recommended response.
  - `[x]` Implement operator disposition controls (Acknowledge, Escalate, Defer, Override) with real-time UI feedback.
  - `[x]` Enforce human approval / policy gate flags before automated containment triggers.
- **Demonstration / Acceptance Criteria:**
  - Dynamic alert queue derives from active simulation events; operator disposition workflow verified in browser and automated tests.

---

### Task 11: Live Intelligence & Reasoning Layer
- **Status:** `[x] Complete` (Implemented, Tested, Demonstrated)
- **Priority:** `HIGH`
- **Dependencies:** Task 2, Task 4, Task 7
- **Scope & Subtasks:**
  - `[x]` Surface deep temporal reasoning: current state $\to$ delta dynamics $\to$ forecast trajectory $\to$ feature attributions.
  - `[x]` Display security hypothesis alongside supporting evidence and suppressing/counter-evidence.
  - `[x]` Show evolution of Future Security Risk score across multi-step forecast horizons ($h=1, 2, 3$).
  - `[x]` Enable interactive step/window inspection across historical and active windows.
- **Demonstration / Acceptance Criteria:**
  - Operator can select any window and inspect the complete causal reasoning chain justifying why the forecast indicates rising threat. Verified in browser and automated test suite.

---

### Task 12: ReconsiderationState & Trajectory Revision Engine
- **Status:** `[ ] Remaining`
- **Priority:** `CRITICAL`
- **Dependencies:** Task 1, Task 4
- **Scope & Subtasks:**
  - `[ ]` Implement discrepancy detector comparing observed telemetry $S_{t+1}$ against previous forecast $\hat{S}_{t+1|t}$.
  - `[ ]` Calculate contradiction score based on directional and magnitude forecast errors.
  - `[ ]` If contradiction exceeds threshold: dynamically decrement trust score, reduce Future Security Risk, downgrade response priority, and emit `RECONSIDERATION_TRIGGERED` event.
  - `[ ]` Surface active `ReconsiderationState` banner in UI showing previous hypothesis, contradiction reason, and revised forecast.
- **Demonstration / Acceptance Criteria:**
  - Feeding contradictory telemetry into an active high-risk forecast immediately lowers trust and risk, updates recommended actions, and logs explicit reconsideration provenance.

---

### Task 13: Window-Level Investigation Workspace
- **Status:** `[ ] Remaining`
- **Priority:** `HIGH`
- **Dependencies:** Task 4, Task 7
- **Scope & Subtasks:**
  - `[ ]` Refactor Investigation view around discrete temporal windows ($W_t$) rather than arbitrary static entities.
  - `[ ]` Provide slice inspection for a selected window: raw telemetry, input deltas, AR(5) forecast output, hypothesis, signatures, and counter-evidence.
  - `[ ]` Implement temporal navigation allowing operator to step backwards and forwards through historical windows.
- **Demonstration / Acceptance Criteria:**
  - Operator can select any window in session history and review the complete state snapshot, forecast, and system reasoning for that exact time slice.

---

### Task 14: Window-Level Evidence & Provenance Explorer
- **Status:** `[ ] Remaining`
- **Priority:** `HIGH`
- **Dependencies:** Task 13
- **Scope & Subtasks:**
  - `[ ]` Structure evidence cards anchored to specific window intervals ($W_t$).
  - `[ ]` Link each evidence artifact to its source: flow telemetry, model weights, feature attributions, and policy evaluation rules.
  - `[ ]` Support side-by-side comparison of supporting vs contradictory evidence for the active security hypothesis.
- **Demonstration / Acceptance Criteria:**
  - Every alert or response recommendation displays an auditable evidence chain traceable to raw window observations and reproducible math.

---

## Phase 4 — Live Legitimacy / Controlled Experiment (⭐ Critical Proof Milestone)

### Task 15: Controlled Network Traffic Generator & Live Ingestion Pipeline
- **Status:** `[ ] Remaining`
- **Priority:** `CRITICAL`
- **Dependencies:** Task 1, Task 4
- **Scope & Subtasks:**
  - `[ ]` Implement lightweight local traffic generator producing real network packets on an isolated loopback/virtual subnet.
  - `[ ]` Capture packets in real-time or feed generated PCAP flows into the existing flow ingestion engine.
  - `[ ]` Aggregate flows into windowed `NetworkState` objects via the authoritative state builder.
  - `[ ]` Stream computed `NetworkState` into the existing AR(5) forecasting pipeline in real time.
  - `[ ]` Enforce strict information boundary: generator outputs only raw network traffic; forecasting stack receives zero future states, labels, or scenario phase cues.
- **Demonstration / Acceptance Criteria:**
  - Live network packets generate authentic flow telemetry, which produces valid `NetworkState` transitions and drives live AR(5) forecasts without precomputed state replay.

---

### Task 16: Multi-Trajectory Branching & Dynamic Contradiction Experiment
- **Status:** `[ ] Remaining`
- **Priority:** `CRITICAL`
- **Dependencies:** Task 12, Task 15
- **Scope & Subtasks:**
  - `[ ]` Implement configurable traffic experiment profiles:
    - **Run A (Escalation):** Normal baseline $\to$ probing bursts $\to$ high-rate resource exhaustion / data movement.
    - **Run B (Aborted Attack):** Normal baseline $\to$ probing bursts $\to$ sudden cessation / return to baseline.
    - **Run C (Altered Trajectory):** Normal baseline $\to$ probing bursts $\to$ unexpected traffic pattern shift.
  - `[ ]` Verify that Run A produces escalating risk and containment recommendation.
  - `[ ]` Verify that Run B and Run C trigger Reconsideration (trust drops, risk drops, containment de-escalates).
- **Demonstration / Acceptance Criteria:**
  - Side-by-side or sequential execution of Runs A, B, and C demonstrates completely divergent, telemetry-driven system responses, proving future state is not hardcoded.

---

### Task 17: Lead Time Measurement & Replay Verification Harness
- **Status:** `[ ] Remaining`
- **Priority:** `HIGH`
- **Dependencies:** Task 15, Task 16
- **Scope & Subtasks:**
  - `[ ]` Implement timestamped audit logging comparing the instant a forecast crosses the intervention threshold ($t_{\text{forecast}}$) against the instant adverse impact manifests ($t_{\text{impact}}$).
  - `[ ]` Calculate empirical defender intervention lead time ($\Delta t = t_{\text{impact}} - t_{\text{forecast}}$).
  - `[ ]` Produce structured test report validating lead time across multiple live experiment runs.
- **Demonstration / Acceptance Criteria:**
  - Automated evaluation harness outputs verified lead time statistics proving the defender receives advance warning before critical state escalation.

---

## Phase 5 — Safe Operational Decision Layer

### Task 18: Service Topology & Dependency Awareness Graph
- **Status:** `[x] Complete`
- **Priority:** `HIGH`
- **Dependencies:** Task 4
- **Scope & Subtasks:**
  - `[x]` Define lightweight topology contract representing nodes, service tiers (e.g., Internet $\to$ API Gateway $\to$ App Server $\to$ Database), and critical dependencies.
  - `[x]` Assign criticality weights and redundancy indicators (e.g., replica available, read-only fallback, single point of failure).
  - `[x]` Expose topology graph query interface for downstream containment evaluation.
- **Demonstration / Acceptance Criteria:**
  - System resolves full dependency chain and criticality score for any target IP/node in the network state.
- **Evidence:** [`core/topology/`](file:///c:/Users/ayush/sih1/core/topology/), [`tests/test_topology.py`](file:///c:/Users/ayush/sih1/tests/test_topology.py) (18/18 passed), [`docs/TOPOLOGY_ARCHITECTURE.md`](file:///c:/Users/ayush/sih1/docs/TOPOLOGY_ARCHITECTURE.md).

---

### Task 19: Containment Safety & Blast-Radius Assessment Engine
- **Status:** `[x] Complete`
- **Priority:** `HIGH`
- **Dependencies:** Task 18
- **Scope & Subtasks:**
  - `[x]` Calculate structural blast radius: identify which downstream dependent services are exposed if candidate node is affected/isolated.
  - `[x]` Compute BFS shortest dependency depth, direct vs transitive impact, and criticality breakdown.
  - `[x]` Compute transparent structural impact heuristic with safe zero-denominator handling.
  - `[x]` Provide explicit KNOWN, PARTIAL (indeterminate coverage), and UNAVAILABLE (unknown impact) semantics.
  - `[x]` Prepare structural blast-radius context for Task 20 containment policy gating.
- **Demonstration / Acceptance Criteria:**
  - System resolves downstream dependents, dependency depth, critical dependents, and weighted structural impact for any focus node in the topology graph.
- **Evidence:** [`core/blastradius/`](file:///c:/Users/ayush/sih1/core/blastradius/), [`tests/test_blast_radius.py`](file:///c:/Users/ayush/sih1/tests/test_blast_radius.py) (22/22 passed), [`docs/BLAST_RADIUS_ARCHITECTURE.md`](file:///c:/Users/ayush/sih1/docs/BLAST_RADIUS_ARCHITECTURE.md).

---

### Task 20: Confidence-to-Authority Mapping & Policy Gate
- **Status:** `[x] Complete`
- **Priority:** `CRITICAL`
- **Dependencies:** Task 1, Task 4, Task 17, Task 18, Task 19
- **Scope & Subtasks:**
  - `[x]` Establish core principle: `HIGH RISK != HIGH AUTHORITY`.
  - `[x]` Implement explicit `AuthorityLevel` (`OBSERVE`, `ALERT`, `RECOMMEND`, `HUMAN_APPROVAL_REQUIRED`, `BLOCKED`).
  - `[x]` Implement `ActionClass` (`OBSERVE_ONLY`, `ALERT_OPERATOR`, `GENERATE_RECOMMENDATION`, `PREPARE_REVERSIBLE_ACTION`, `EXECUTE_REVERSIBLE_ACTION`, `EXECUTE_DESTRUCTIVE_ACTION`).
  - `[x]` Enforce conservative invariants: low trust / high uncertainty constrains authority; unavailable topology blocks execution/preparation; partial topology mandates human approval; destructive actions permanently blocked; blast radius increases urgency without expanding authority.
  - `[x]` Reuse project's explicit uncertainty contract (`FutureSecurityRiskScore.uncertainty` and horizon-specific uncertainties); reject synthetic `1.0 - trust`. Fail closed on missing, NaN, or out-of-bounds metrics.
  - `[x]` Integrate with closed-loop reconsideration (evaluates against current canonical revised values).
  - `[x]` Prove 3 monotonicity properties (trust, uncertainty, topology).
  - `[x]` Additive integration into `DemoEvent.authority_policy` with deterministic SHA-256 provenance hashes.
- **Demonstration / Acceptance Criteria:**
  - High risk with low trust or high uncertainty restricts authority to advisory-only; destructive actions permanently blocked; 27/27 dedicated unit tests pass, full regression suite passing.
- **Evidence:** [`core/authority/`](file:///c:/Users/ayush/sih1/core/authority/), [`tests/test_authority_policy.py`](file:///c:/Users/ayush/sih1/tests/test_authority_policy.py) (27/27 passed), [`docs/AUTHORITY_POLICY_ARCHITECTURE.md`](file:///c:/Users/ayush/sih1/docs/AUTHORITY_POLICY_ARCHITECTURE.md).

---

### Task 21: Reversible Targeted Response Execution & Outcome Verification
- **Status:** `[x] Complete`
- **Priority:** `HIGH`
- **Dependencies:** Task 19, Task 20
- **Scope & Subtasks:**
  - `[x]` Implement reversible response primitives (`RATE_LIMIT_IP`, `TEMPORARY_BLOCK_IP`, `ISOLATE_SERVICE_ENDPOINT`, `REROUTE_SUSPECT_TRAFFIC`, `STEP_UP_CHALLENGE`).
  - `[x]` Permanently block destructive actions (`EXECUTE_DESTRUCTIVE_ACTION`).
  - `[x]` Enforce mandatory human approval token bound to exact `action_id`, `authority_decision_id`, and `evidence_window_id`.
  - `[x]` Enforce deterministic stale-authorization revalidation (superseded evidence window, unavailable topology, snapshot mismatch, missing target node).
  - `[x]` Implement controlled rollback as a first-class action governed by `RollbackPolicy` (`AUTOMATIC_COMPENSATING` vs `REQUIRE_HUMAN_APPROVAL`), authority-gated against Task 20.
  - `[x]` Implement safe in-memory simulation adapter (`DemoResponseAdapter`) with zero host/OS/firewall modifications.
  - `[x]` Implement post-mitigation telemetry outcome verifier with fail-closed behavior on missing evidence (`INSUFFICIENT_EVIDENCE`).
  - `[x]` Generate `OutcomeMismatchHandoff` for Task 17 Reconsideration without synthesizing fake risk scores.
  - `[x]` Additive integration with `DemoEvent` and SSE stream with SHA-256 provenance hashes.
- **Demonstration / Acceptance Criteria:**
  - Executing an approved simulated containment action verifies post-action telemetry; outcome mismatches feed back to Reconsideration; rollback is controlled and authority-gated; 32/32 dedicated tests pass (389/389 total test suite pass).
- **Evidence:** [`core/response_execution/`](file:///c:/Users/ayush/sih1/core/response_execution/), [`tests/test_response_execution.py`](file:///c:/Users/ayush/sih1/tests/test_response_execution.py) (23/23 passed), [`tests/test_outcome_verification.py`](file:///c:/Users/ayush/sih1/tests/test_outcome_verification.py) (9/9 passed), [`docs/RESPONSE_EXECUTION_ARCHITECTURE.md`](file:///c:/Users/ayush/sih1/docs/RESPONSE_EXECUTION_ARCHITECTURE.md).

---

## Phase 6 — Persistence, Audit & Hardening

### Task 22: SQLite Persistence Layer & Session Audit Trail
- **Status:** `[x] Complete`
- **Priority:** `MEDIUM`
- **Dependencies:** Task 4, Task 17, Task 18, Task 19, Task 20, Task 21
- **Scope & Subtasks:**
  - `[x]` Implement transactional SQLite database storing all first-class artifacts across Tasks 17–21.
  - `[x]` Enforce clear architectural separation between Current State, Audit History, Derived Artifacts, and Provenance.
  - `[x]` Implement append-only cryptographic audit chain linking sequential events with SHA-256 hashes.
  - `[x]` Explicit security boundary: append-only is enforced at application/store API level; unauthorized direct filesystem/db tampering is detectable and fails closed, not physically impossible.
  - `[x]` Enforce canonical JSON serialization with explicit versioned schemas (`schema_version = 1`); reject future/missing schemas.
  - `[x]` Implement automatic secret redaction and path traversal attack prevention.
  - `[x]` Implement startup consistency recovery checking with orphan cross-reference detection.
  - `[x]` Provide deterministic portable audit bundle export and import with bundle hash verification.
- **Demonstration / Acceptance Criteria:**
  - Session state and audit artifacts survive process restart; duplicate executions remain idempotent; database tampering is detected and fails closed; 36/36 dedicated tests pass (425/425 total regression suite pass).
- **Evidence:** [`core/persistence/`](file:///c:/Users/ayush/sih1/core/persistence/), [`tests/test_persistence.py`](file:///c:/Users/ayush/sih1/tests/test_persistence.py) (17/17 passed), [`tests/test_recovery.py`](file:///c:/Users/ayush/sih1/tests/test_recovery.py) (11/11 passed), [`tests/test_integrity_hardening.py`](file:///c:/Users/ayush/sih1/tests/test_integrity_hardening.py) (8/8 passed), [`docs/PERSISTENCE_HARDENING_ARCHITECTURE.md`](file:///c:/Users/ayush/sih1/docs/PERSISTENCE_HARDENING_ARCHITECTURE.md).

---

### Task 23: Fail-Safe Handling & Graceful Degradation Protocol
- **Status:** `[ ] Remaining`
- **Priority:** `HIGH`
- **Dependencies:** Task 4, Task 20
- **Scope & Subtasks:**
  - `[ ]` Implement fail-safe guards across all failure modes: telemetry loss, model timeout/exception, missing dependency data, contradictory signals.
  - `[ ]` When telemetry is interrupted: preserve system stability, flag state as stale, drop authority to zero, and notify operator.
  - `[ ]` When model fails: fallback to deterministic heuristic baseline without crashing the server.
- **Demonstration / Acceptance Criteria:**
  - Severing telemetry or injecting corrupt packets leaves the backend operating safely in an unprivileged, alert-only degraded state.

---

### Task 24: Concurrency, Rate Limiting & Input Validation Hardening
- **Status:** `[ ] Remaining`
- **Priority:** `MEDIUM`
- **Dependencies:** Task 5, Task 6
- **Scope & Subtasks:**
  - `[ ]` Enforce Pydantic schema validation on all incoming API payloads.
  - `[ ]` Add thread locking around shared state mutations in `RuntimeStateStore`.
  - `[ ]` Bound memory consumption for historical buffers and SSE queues.
- **Demonstration / Acceptance Criteria:**
  - Fuzz testing and malformed payload injection fail gracefully with HTTP 422/400 without unhandled exceptions or state corruption.

---

## Phase 7 — Validation, Load & Deployment

### Task 25: SSE Load Testing & Multi-Client Session Stress Testing
- **Status:** `[ ] Remaining`
- **Priority:** `MEDIUM`
- **Dependencies:** Task 6
- **Scope & Subtasks:**
  - `[ ]` Stress test SSE streaming endpoint with 20+ concurrent active browser connections.
  - `[ ]` Validate long-running session stability (>1 hour continuous execution) without memory leaks.
  - `[ ]` Ensure disconnect/reconnect cycles do not orphan background streaming tasks.
- **Demonstration / Acceptance Criteria:**
  - Automated benchmark confirms stable latency and constant memory footprint under sustained multi-client SSE broadcast.

---

### Task 26: Unified One-Command Deployment & Reproducible Demonstration Package
- **Status:** `[ ] Remaining`
- **Priority:** `HIGH`
- **Dependencies:** Task 9, Task 15, Task 16, Task 21
- **Scope & Subtasks:**
  - `[ ]` Create unified startup script launching backend FastAPI, traffic generator, and UI dev server.
  - `[ ]` Package pre-recorded evaluation captures and live experiment presets.
  - `[ ]` Document judge evaluation script detailing step-by-step reproduction of the canonical demo loop.
- **Demonstration / Acceptance Criteria:**
  - Running a single command boots the entire environment cleanly and enables an evaluator to reproduce the complete proof workflow without manual configuration.

---

# CURRENT PROJECT STATE

### Completed Core Capabilities
1. **Authoritative Forecasting:** Real AR(5) model trained on CIC-IDS2018 achieving 68.10% directional accuracy on held-out infiltration blocks, integrated with feature attribution explainability.
2. **Robust Runtime Foundation:** Thread-safe `RuntimeStateStore`, `DemoAdapter` lifecycle controller, FastAPI REST endpoints (including `/api/v1/demo/speed`), and SSE streaming pipeline operational.
3. **Reactive Control Centre:** Modern React UI wired directly to backend SSE events:
   - **Operational Simulation (Task 9):** Real operator controls (`START`, `PAUSE`, `RESUME`, `STEP`, `RESET`, speed multipliers), live command logs, and network trajectory with forward AR(5) forecast cones.
   - **Alerts Queue (Task 10):** Decision-support queue bound to runtime events with operator disposition (`ACKNOWLEDGE`, `ESCALATE`, `DEFER`, `OVERRIDE`) and policy approval gates.
   - **Predictive Intelligence (Task 11):** Deep causal reasoning chain exposing delta dynamics, multi-step Future Security Risk ($h=1,2,3$), AR(5) lag breakdowns ($p=1\dots 5$), and supporting/counter-evidence.

### Strongest Remaining Proof Gap
- **Live Legitimacy Barrier:** The system currently runs on pre-orchestrated scenario states. To definitively defeat the criticism that *"this is just a prerecorded replay,"* the system must ingest live, unscripted network flows from a real traffic source, prove zero future-state leakage, and demonstrate dynamic reconsideration when traffic patterns deviate or abort.

### Next 3 Highest-Priority Tasks
1. **Task 15: Controlled Network Traffic Generator & Live Ingestion Pipeline (`CRITICAL`)** — Generate actual live network traffic, compute `NetworkState` dynamically, and feed the live forecasting stack with zero future leakage.
2. **Task 12: ReconsiderationState & Trajectory Revision Engine (`CRITICAL`)** — Detect when observed telemetry contradicts previous forecasts, dynamically reducing trust, risk, and authority.
3. **Task 16: Multi-Trajectory Branching & Dynamic Contradiction Experiment (`CRITICAL`)** — Demonstrate divergent system outcomes across Runs A (escalation), B (cessation), and C (trajectory shift).

### Final Intended End-to-End Demonstration
$$\text{Observe Baseline} \longrightarrow \text{Forecast AR(5)} \longrightarrow \text{Explain Rationale} \longrightarrow \text{Assess Blast Radius} \longrightarrow \text{Contain Safely (Reversible)} \longrightarrow \text{Observe New Telemetry} \longrightarrow \text{Reconsider}$$
1. Normal baseline network traffic is generated and observed.
2. Suspicious temporal shift emerges; AR(5) engine forecasts rising risk 20–30 seconds before peak impact and explains the driving features.
3. The system maps affected services to the dependency graph, determines that isolating the primary server would cause an outage, and downgrades the action to targeted egress throttling under human approval.
4. Live traffic pattern is altered (attack aborts or changes vector); contradictory telemetry arrives.
5. System reduces trust, lowers Future Security Risk, de-escalates containment, and records the full reconsideration provenance.
