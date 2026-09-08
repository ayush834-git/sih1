# SIH 26153 — Updated Master Workflows

## Phase 1 — Forecasting Foundation ✅

### 1. Real AR(5)
Already complete.
`CIC-IDS2018 → training → AR(5) → persisted authoritative model → runtime loading`

Evidence:
* 68.10% directional accuracy
* Chronological test split
* Statistical validation against AR(3)
* 4/4 held-out infiltration blocks
* Round-trip model equivalence

### 2. Explainability integration ✅
Runtime now produces:
`forecast → feature contributions + security explanation`

Provides an evidence trail for *why* the prediction exists.

---

## Phase 2 — Runtime Foundation ✅

### 3. DemoAdapter ✅
Controls:
`START / PAUSE / RESUME / STEP / RESET / SPEED`

### 4. RuntimeStateStore ✅
Single source of truth for:
`session → state → events → history → status`

### 5. FastAPI ✅
The runtime is queryable and controllable through real API endpoints.

### 6. SSE ✅
Architecture:
```text
Backend runtime
     ↓
    SSE
     ↓
React Control Centre
```
No frontend polling architecture.

### 7. React runtime integration ✅
Shared `RuntimeSnapshot` drives the live UI.

Current working chain:
```text
LiveDemoEngine
      ↓
DemoAdapter
      ↓
RuntimeStateStore
      ↓
   FastAPI
      ↓
    SSE
      ↓
   React
```

---

## Phase 3 — Turn the Runtime into an Operational Security Prototype

### 8. Live Overview ✅
Operator summary demonstrating:
* Current telemetry
* Forecast
* Future security risk
* Stage
* Confidence
* Priority
* Signatures
* Trust
* Recommended response
* Explainability

### 9. Live Simulation — Controlled Experiment & Operator Control Surface
Redefined from simple demo playback to:
> **The controlled experiment and operator-control surface.**

Exposes:
```text
Scenario / experiment
        ↓
START / PAUSE / RESUME / STEP / RESET
        ↓
Engine status
        ↓
Live command log
        ↓
Current network trajectory
        ↓
Forecast
        ↓
Risk
        ↓
Decision
```

**Architectural Boundary:** DemoAdapter controls the experiment execution; it must never become the source of truth for future network states.

### 10. Live Alerts — Operational Attention
Answers:
> **“What requires attention right now, and why?”**

Connects:
```text
Observed behaviour
       ↓
    Forecast
       ↓
Security interpretation
       ↓
Confidence / uncertainty
       ↓
    Priority
       ↓
Recommended action
       ↓
Authority level
       ↓
Human approval / policy gate
```

### 11. Live Intelligence — Reasoning Layer
Answers:
> **“Why is the risk rising?”**

Reveals:
```text
Current state
      ↓
Temporal changes
      ↓
Forecast trajectory
      ↓
Feature contribution
      ↓
Security hypothesis
      ↓
Supporting / suppressing evidence
      ↓
Future security risk
```

### 12. ReconsiderationState — Epistemic Humility
Explicitly represents:
> **What happens when reality stops agreeing with the forecast?**

```text
       Forecast
          ↓
New telemetry arrives
          ↓
Compare expected vs observed
          ↓
    Contradiction?
          ↓ YES
       Trust ↓
       Risk ↓
     Authority ↓
Recommendation reconsidered
```
Demonstrates that the system is not blindly committed to its initial prediction.

### 13. Window-Level Investigation
Investigation revolves around:
> **A suspicious temporal window** (e.g. Window W17, 10:32:10 → 10:32:20)

Exposes:
* Observed telemetry
* Forecast
* Security hypothesis
* Confidence
* Risk trajectory
* Signatures
* Counter-evidence
* Recommended action

### 14. Window-Level Evidence
Builds coherent provenance:
```text
Evidence for Window W17
        ↓
Observed telemetry
        ↓
Forecast inputs
        ↓
Forecast output
        ↓
Security reasoning
        ↓
Supporting evidence
        ↓
Contradictory evidence
        ↓
Decision provenance
```

---

## Phase 4 — Reality / Legitimacy Layer

### 15. Controlled Live Traffic Source ⭐ Critical
The central technical milestone proving prediction legitimacy:

```text
                    CONTROLLED EXPERIMENT
                           ↓
                    Traffic generator
                           ↓
                   Actual network traffic
                           ↓
                     Flow telemetry
                           ↓
                     State builder
                           ↓
                  Existing forecasting stack
```

**Legitimacy Rule:** The forecasting engine must **never** receive future NetworkStates, attack labels, scenario phase labels, or expected trajectories. It receives strictly what the telemetry pipeline observed.

**Deliberate Future Variations (Experiment Branching):**
* **Run A:** normal → suspicious → escalation
* **Run B:** normal → suspicious → stop
* **Run C:** normal → suspicious → changed trajectory

Proves: **The future is produced by the experiment, not pre-supplied to the prediction system.**

---

## Phase 5 — Safe Operational Reasoning (Systems-Engineering Layer)

### Mature Operational Pipeline
```text
                 LIVE TELEMETRY
                       ↓
                 NETWORK STATE
                       ↓
                  TRAJECTORY
                       ↓
                   FORECAST
                       ↓
               TRUST / UNCERTAINTY
                       ↓
              SECURITY INTERPRETATION
                       ↓
               FUTURE SECURITY RISK
                       ↓
          ┌────────────┴────────────┐
          ↓                         ↓
   SERVICE CRITICALITY        DEPENDENCIES
          └────────────┬────────────┘
                       ↓
             CONTAINMENT ANALYSIS
                       ↓
             AUTHORITY DECISION
                       ↓
             HUMAN / POLICY GATE
                       ↓
              REVERSIBLE ACTION
                       ↓
              VERIFY OUTCOME
                       ↓
                 NEW TELEMETRY
                       ↓
                RECONSIDERATION
```

### Confidence → Authority Principle
Uncertainty directly governs permissible automated action:
* **High Confidence + Strong Evidence + Safe Isolation:** Higher permitted automated authority.
* **Medium Confidence:** Limited / reversible action with operator involvement.
* **Low Confidence / Novel Behaviour:** Zero aggressive automated action; human escalation.

### Dependency + Service Continuity
Avoids catastrophic self-inflicted outages (`"Isolate DB"`):
* Can the node be isolated safely?
* Will dependent services fail?
* Can the service degrade gracefully?
* Is there a replica / fallback path?
* What is the blast radius?

**Value proposition:** *Contain the attack without becoming the cause of the outage.*

---

## Phase 6 — Persistence / Hardening

### 16. SQLite Persistence
Persist:
* Runtime sessions
* Events
* Investigations
* Evidence
* Audit records
* Decision history

### 17. Hardening & Fault Tolerance
Test for:
* Malformed input
* Runtime failures & telemetry loss
* Prediction failure & contradictory evidence
* Unsafe response conditions & authorization boundaries
* Failure-safe behavior: *“When assumptions fail, fail safely.”*

### 18. Load Testing
Validate multi-client SSE stability, high event throughput, long-running sessions, and bounded memory.

### 19. Deployment
Single reproducible command startup:
`Traffic Source → Backend Telemetry → Forecasting → API/SSE → Control Centre`

---

## The Canonical 26153 Demo Workflow

```text
                    NORMAL NETWORK
                          ↓
                    Observe baseline
                          ↓
             Suspicious behaviour emerges
                          ↓
                  Temporal change detected
                          ↓
                    AR(5) forecast
                          ↓
                 Future risk increases
                          ↓
                System explains WHY
                          ↓
             Affected scope identified
                          ↓
             Confidence / authority assessed
                          ↓
             Targeted response recommended
                          ↓
                  Human / policy gate
                          ↓
          Reversible containment / preparation
                          ↓
                 Service kept alive
                          ↓
              Traffic trajectory changes
                          ↓
                 Contradictory evidence
                          ↓
                    Trust decreases
                          ↓
                      Risk decreases
                          ↓
                    Reconsideration
```

---

## Cloudflare-Complementary Positioning

```text
Existing security infrastructure
Cloudflare / IDS / Firewall / EDR / SIEM
                  ↓
               Telemetry
                  ↓
        ┌─────────────────────┐
        │ OUR PREDICTIVE LAYER│
        └─────────────────────┘
                  ↓
        Forecast evolution
                  ↓
        Future security context
                  ↓
       Decision / intervention time
                  ↓
       Existing enforcement systems
```

**Positioning Statement:**
> *“We are not building a student version of Cloudflare or replacing existing perimeter defenses. We are building a predictive intelligence layer that sits above existing telemetry to turn evolving network dynamics into defensive intervention time before consequences become irreversible.”*

---

## Revised Project Progression

* **Phase 1:** Can we forecast? ✅
* **Phase 2:** Can we run it as a system? ✅
* **Phase 3:** Can an operator actually use it? 🔄
* **Phase 4:** Does it work on live controlled traffic? ⭐
* **Phase 5:** Can it make safe containment decisions? 🔜
* **Phase 6:** Can it survive failure and deployment? 🔜

**Canonical Closed Loop:**
> **Observe → Forecast → Explain → Decide → Contain safely → Observe again → Reconsider.**
