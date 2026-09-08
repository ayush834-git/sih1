# Empirical Forecast Lead-Time Methodology & Evaluation (Task 16)

## 1. Governing Epistemic Principle

> **Forecast Horizon $\neq$ Actionable Lead Time**
>
> A 10-second multi-step prediction horizon ($h=1, 2, 3$) is a formal property of the autoregressive state-space transition model:
> $$\hat{\Delta S}_{t+h} = \sum_{k=1}^{p} \mathbf{A}_k \hat{\Delta S}_{t+h-k}$$
> It **does not** automatically establish 10 seconds of usable operational warning for a human Security Operations Center (SOC) or automated mitigation playbook.

Operational lead time depends strictly on three physical and operational criteria:
1. **Early Behavioural Divergence**: Threat momentum or reconnaissance probing must induce measurable state drift *prior* to peak attack volume.
2. **Actionable Response Margin**: The predictive signal must arrive early enough for a defensive countermeasure (e.g. firewall rule push, BGP diversion, sandbox isolation, session drain) to complete execution *before* sustained attack impact manifests.
3. **Selectivity & False Alarm Cost**: An uncalibrated detector firing prematurely on benign fluctuation produces false lead time, degrading SOC trust.

---

## 2. Methodology Guards Applied

### Guard 1: Modeled Action Duration Assumption
The 20-second defensive preparation requirement is explicitly a **modeled experimental assumption**, denoted:
$$\text{modeled\_action\_duration\_s} = 20$$
It is **not** an empirically standardized SOC response time. Enterprise SOC triage times vary widely from automated millisecond playbooks to multi-minute human analyst review.

To prevent over-reliance on the 20s assumption, the evaluation includes a **sensitivity analysis** across:
$$T_{\text{action}} \in \{5\text{s}, 10\text{s}, 20\text{s}, 30\text{s}\}$$
reporting exactly how actionable success rates change as a function of defensive readiness.

### Guard 2: Separation of Evaluation Tiers
- **Tier 1: Live Controlled Behavioural Progression**:
  - Captured on Windows hardware using genuine Npcap 1.88 and TShark on `\Device\NPF_Loopback`.
  - Proves that the end-to-end packet $\to$ flow $\to$ 10-second state $\to$ AR(5) $\to$ trajectory pipeline detects and forecasts a controlled behavioural escalation earlier than a configured current-state detector.
  - **Explicit Limitation**: These runs are strictly controlled laboratory progressions (port exploration, connection churn). They are **not** labeled as real attacker kill-chain attack progression.
- **Tier 2: Dataset Ground-Truth Attack Progression**:
  - Evaluated on contiguous benchmark state sequences from the CSE-CIC-IDS2018 dataset (Wednesday-28 Infiltration and Thursday-01 Infiltration onsets).
  - Evaluates true attack onset timing and sustained malicious execution against verified ground-truth labels.

---

## 3. Mathematical Formalism

### 3.1 Time Discretization & Windows
Network telemetry is organized into non-overlapping 10-second causal observation windows:
$$w \in \{0, 1, 2, \dots, W-1\}, \quad t(w) = w \times 10.0\text{s}$$

For each scenario, we observe four critical epoch markers:
- $w_{\text{suspicious}}$: First window showing behavioural shift or exploratory momentum.
- $w_{\text{pred}}$: First window where the predictive trajectory detector fires ($\text{alert}=\text{true}$).
- $w_{\text{base}}$: First window where the conventional current-state detector fires.
- $w_{\text{actual}}$: Window of sustained ground-truth attack or controlled escalation onset.

### 3.2 Lead Time Definitions
1. **Lead Time versus Baseline Detector ($\Delta t_{\text{base}}$)**:
   $$\Delta t_{\text{base}} = (w_{\text{base}} - w_{\text{pred}}) \times 10.0\text{s}$$
   A positive value indicates that the forecasting system detected the impending escalation prior to the conventional threshold detector.

2. **Lead Time versus Actual Attack Onset ($\Delta t_{\text{actual}}$)**:
   $$\Delta t_{\text{actual}} = (w_{\text{actual}} - w_{\text{pred}}) \times 10.0\text{s}$$
   A positive value indicates the warning arrived before sustained attack manifestation.

### 3.3 Actionable Response Criterion
For a given defensive preparation duration $T_{\text{action}}$:
$$\text{Actionable}(T_{\text{action}}) = \begin{cases} 
\text{True}, & \text{if } w_{\text{pred}} < w_{\text{base}} \land \Delta t_{\text{actual}} \ge T_{\text{action}} \\
\text{False}, & \text{otherwise}
\end{cases}$$

---

## 4. Failure Taxonomy

Every progression scenario run is classified into one of five mutually exclusive operational categories:

| Category | Definition | Operational Consequence |
|---|---|---|
| **`NONE` (Clean Success)** | Fired strictly before baseline detector AND allowed $\ge 20\text{s}$ action margin before actual onset. | Complete defensive mitigation before attack impact. |
| **`INSUFFICIENT_TIME`** | Fired before baseline and actual onset, but lead time was $< 20\text{s}$ (e.g. 10s warning). | Partial mitigation; defensive actions interrupted by attack arrival. |
| **`LATE_VS_BASELINE`** | Predictive alert fired at or after the conventional current-state baseline alert. | Zero operational advantage over conventional monitoring. |
| **`MISSED`** | Escalation manifested, but predictive detector failed to trigger prior to or during the event. | Full unmitigated attack impact. |
| **`FALSE_EARLY`** | Predictive detector fired during benign baseline traffic without any subsequent escalation. | Unwarranted defensive action, analyst fatigue, operational disruption. |

---

## 5. Quantitative Results & Sensitivity Analysis Findings

### 5.1 Progression Runs Evaluated
- **Total Progression Scenarios**: 17 runs
  - **Tier 1 (Live Hardware Capture)**: 5 runs on Windows Npcap 1.88 / TShark (`\Device\NPF_Loopback`)
    - 2x `recon_progression`
    - 2x `churn_progression`
    - 1x `clean_baseline` (Negative control)
  - **Tier 2 (Dataset Ground-Truth)**: 12 contiguous slices from CSE-CIC-IDS2018 (Wednesday-28 Infiltration & Thursday-01 Infiltration)
    - 4x Infiltration attack onset sequences
    - 8x Benign control sequences
- **Escalation / Attack Runs Evaluated for Lead Time**: 8 runs

### 5.2 Empirical Lead-Time Statistics

| Metric | Lead Time vs Baseline Detector ($\Delta t_{\text{base}}$) | Lead Time vs Actual Attack Onset ($\Delta t_{\text{actual}}$) |
|---|:---:|:---:|
| **Mean** | **`8.75s`** | **`20.00s`** |
| **Median** | **`5.0s`** | **`20.0s`** |
| **Standard Deviation** | `11.26s` | `10.69s` |
| **Min / Max** | `0.0s` / `30.0s` | `10.0s` / `30.0s` |
| **Interquartile Range (IQR)** | `12.5s` | `20.0s` |
| **95% Bootstrap CI** | **`[2.50s, 16.25s]`** | **`[12.50s, 27.50s]`** |

---

### 5.3 Sensitivity Analysis across Modeled Action Durations ($T_{\text{action}}$)

| Modeled Action Duration ($T_{\text{action}}$) | Actionable Runs | Total Escalation Runs | Actionable Success Rate (%) | Interpretation |
|---|:---:|:---:|:---:|---|
| **5 seconds** | 6 | 8 | **`75.0%`** | Automated playbooks (API route updates, BGP Flowspec) execute with high success margin. |
| **10 seconds** | 6 | 8 | **`75.0%`** | Fast semi-automated workflows (pre-warming filters, firewall rules) achieve robust actionable coverage. |
| **20 seconds (Default Assumption)** | 2 | 8 | **`25.0%`** | Strict 20s human preparation assumption filters out 10s warnings as `INSUFFICIENT_TIME`. |
| **30 seconds** | 2 | 8 | **`25.0%`** | Multi-hop human review or ticket creation frequently exceeds available early lead time. |

> [!IMPORTANT]
> **Empirical Proof of Methodology Guard 1**:
> The actionable success rate falls from **75.0%** at $T_{\text{action}} \le 10\text{s}$ down to **25.0%** at $T_{\text{action}} = 20\text{s}$.
> This proves that the 20-second threshold is a *modeled experimental assumption* that heavily penalizes warnings arriving with 10s of advance time, rather than a universal property of the forecasting model.

---

### 5.4 Outcome & Failure Case Distribution

```
  Clean Success (NONE)           : 6 runs (35.3%)  [Preceded baseline, actionable margin >= 20s or clean negative control]
  Insufficient Prep Time         : 4 runs (23.5%)  [Preceded baseline & onset with 10s margin, < 20s default assumption]
  False Early Alarms             : 5 runs (29.4%)  [Pre-attack sensitivity triggered on high-volume benign fluctuations]
  Late vs Baseline Detector      : 2 runs (11.8%)  [Fired concurrently at w=0 on Thursday infiltration blocks]
  Missed Escalation              : 0 runs (0.0%)   [All escalation and attack events were captured]
```

---

## 6. Operational Trade-Offs (No Manufactured Superiority)

The empirical evaluation intentionally exposes the legitimate operational trade-off between predictive forecasting and current-state detection:

```
                  ┌─────────────────────────────────────────────────────────────┐
                  │                OPERATIONAL DETECTION SPECTRUM               │
                  └─────────────────────────────────────────────────────────────┘

       PREDICTIVE TRAJECTORY DETECTOR (AR(5))        CONVENTIONAL CURRENT-STATE DETECTOR
       ──────────────────────────────────────        ───────────────────────────────────
       • Earlier Alert Signal (+8.8s to +20.0s)      • Zero Advance Warning (0s Lead Time)
       • High Pre-Attack Sensitivity                 • Near-Zero False Positive Rate (FPR)
       • Catches Velocity & Momentum                 • Waits for Confirmed Threshold Breach
       • Higher False Alarm Risk on Volatility       • Lower Recall on Fast Multi-Vector Spikes
```

### Realistic SOC Deployment Recommendation:
The purpose of forecasting is **not** to replace static or signature detection, but to enable **staged, graduated defense**:
1. **$t - 20\text{s}$ (Predictive Alert)**: Non-disruptive pre-emptive actions:
   - Pre-warm WAF inspection nodes and scale reverse-proxy capacity.
   - Elevate NetFlow/sFlow sampling rate to 1:1 packet capture for the affected subnet.
   - Stage BGP Flowspec route announcements in standby mode.
2. **$t = 0$ (Confirmed Baseline Breach)**: Disruptive mitigation:
   - Apply hard IP blackholing, session teardown, or host isolation.
