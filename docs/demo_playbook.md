# SIH 26153 — Real-Time Controlled Telemetry Demo Playbook

## 1. Executive Summary & Core Concept
This document serves as the operational playbook for demonstrating the SIH 26153 Cyber Predictive Intelligence pipeline.

The demonstration proves the complete end-to-end operation:
$$\text{Raw Telemetry} \to \text{NetworkState} \to \text{AR(5) Dynamics} \to \text{Future Trajectories} \to \text{Security Bridge} \to \text{Priority} \to \text{Role Relevance} \to \text{Human-Gated Response}$$

> [!IMPORTANT]
> **Strict Claim Boundary**: This is a **controlled telemetry-driven attack simulation and replay**. It does **NOT** perform raw packet sniffing, live network interception, or automated mitigation. The system recommends actions, but **NEVER** executes them autonomously.

---

## 2. What the Judge Sees (The 15-Second Canonical Demo)

```
[00.0] NETWORK STATE ........ NORMAL (PortDiv=2, Flows=12, ByteRate=1,500 B/s)
[02.0] BEHAVIOUR ............ Port diversity rising (PortDiv=6 -> 16, SYN=0.25)
[04.0] FORECAST ............. Multi-step exploration growth predicted (Delta=+12.0)
[06.0] SECURITY ............. Reconnaissance hypothesis (Confidence=0.85)
[07.0] PRIORITY ............. MEDIUM (Score: 0.482)
[08.0] ROUTING .............. SOC_ANALYST         [✓ RELEVANT]
[08.0] ROUTING .............. NETWORK_DEFENDER    [✓ RELEVANT]
[08.0] ROUTING .............. ENDPOINT_ANALYST    [✗ NOT RELEVANT]
[08.0] ROUTING .............. DATA_PROTECTION     [✗ NOT RELEVANT]
[10.0] OBSERVATION .......... Telemetry drops (PortDiv=14 -> 5, Forecast Contradicted)
[11.0] TRUST ................ LOW (Confidence recomputed to 0.40)
[12.0] PRIORITY ............. INFO (Score: 0.173 - Dampened without blind escalation)
[13.0] NOTIFICATION ......... De-escalation update dispatched
[14.0] RESPONSE ............. Strategy.MONITOR (Reversible Telemetry Inspection)
[15.0] HUMAN APPROVAL ....... REQUIRED (Zero Automated Execution)
```

---

## 3. Step-by-Step Computational Breakdown

| Step | Logical Time | Computational Action | System Outputs |
| :--- | :--- | :--- | :--- |
| **T0** | $00\text{s}$ | Ingests baseline `NetworkState` ($D_{\text{port}}=2$). | Stage: `Unknown`, Priority: `LOW`, Notifs: $0$. |
| **T1** | $10\text{s}$ | Subtle deviation ($D_{\text{port}}=6$, Flows=25). | Telemetry recorded; AR history buffer updated. |
| **T2** | $20\text{s}$ | Port exploration begins ($D_{\text{port}}=16$, $\text{SYN}=0.25$). | Signature: `RECONNAISSANCE_PORT_EXPLORATION`. |
| **T3** | $30\text{s}$ | AR(5) forecast predicts multi-step growth ($\Delta_{\text{port}}=+12.0$). | Multi-future trajectory generated ($K=3$). |
| **T4** | $40\text{s}$ | Behavioral Security Bridge evaluates forecast reinforcement. | Primary Stage: `Reconnaissance` ($\text{Conf}=0.85$). |
| **T5** | $50\text{s}$ | PriorityEngine evaluates consequence, proximity, likelihood. | Priority: `MEDIUM` ($\text{Score}=0.482$). |
| **T6** | $60\text{s}$ | RoleRelevanceEngine evaluates operational profiles. | **NOT EVERYONE GETS ALERT**: `SOC_ANALYST` ✓, `NETWORK_DEFENDER` ✓, `ENDPOINT_ANALYST` ✗, `DATA_PROTECTION` ✗. |
| **T7** | $70\text{s}$ | Residual bootstrap uncertainty intervals computed. | Marginal 90% prediction intervals visualized. |
| **T8** | $80\text{s}$ | New telemetry observation arrives ($D_{\text{port}}=14 \to 5$). | Rolling context refreshed; deceleration noted. |
| **T9** | $90\text{s}$ | Telemetry contradicts continuation forecast. | Counter-evidence added: *"Immediate deceleration"*. |
| **T10** | $100\text{s}$ | TrustAssessment recomputed with model disagreement. | Model Trust: `LOW` ($\text{Composite}=0.35$). |
| **T11** | $110\text{s}$ | PriorityEngine dampens priority score. | Priority drops to `INFO` ($\text{Score}=0.173$). |
| **T12** | $120\text{s}$ | NotificationEngine dispatches de-escalation update. | Operators receive updated context. |
| **T13** | $130\text{s}$ | ResponseRecommendationEngine shifts strategy. | Strategy: `Strategy.MONITOR` (`ActionType.INCREASE_MONITORING`). |
| **T14** | $140\text{s}$ | Safety verification of recommendation. | `requires_human = True`, `is_reversible = True`. |
| **T15** | $150\text{s}$ | Final state reached and audit log closed. | Machine-readable `events.jsonl` finalized. |

---

## 4. Key Highlights to Demonstrate to Judges

### A. Role-Specific Selective Routing (Not Everyone Gets the Alert)
- **SOC Analyst:** Receives triage alert with port expansion telemetry and triage queue link.
- **Network Defender:** Receives boundary alert with connection table and ACL review recommendations.
- **Endpoint Analyst:** **Excluded** (`NOT_RELEVANT`) because host/EDR telemetry is unavailable in NetFlow.
- **Data Protection Officer:** **Excluded** (`NOT_RELEVANT`) because no exfiltration activity is present.

### B. The Reconsideration Loop (Self-Correcting Intelligence)
- When telemetry at T8 contradicts the forecast at T3, the system does **not** stubbornly escalate.
- Trust decays, confidence is suppressed ($0.85 \to 0.40$), and priority drops (`MEDIUM` $\to$ `INFO`), avoiding alarm fatigue.

### C. Strict Human-in-the-Loop Safety
- All recommendations enforce:
  1. `requires_human = True`
  2. `is_reversible = True`
  3. No autonomous firewall, blocking, or host isolation actions exist.

---

## 5. Negative Claim Boundaries (What We Must NOT Claim)
1. We do **not** claim production packet sniffing (we ingest validated 10-second `NetworkState` windows).
2. We do **not** claim autonomous attack prevention (all response is human-gated).
3. We do **not** claim open-loop 30-second accuracy (we rely on rolling one-step observation refreshes).
4. We do **not** claim MITRE ATT&CK detection certainty (ATT&CK is an explanatory candidate mapping layer).
