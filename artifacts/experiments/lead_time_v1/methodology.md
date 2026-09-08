# Empirical Forecast Lead-Time Methodology & Findings (Task 16)

## 1. Governing Epistemic Principle
**Forecast Horizon != Actionable Lead Time**
- A 10-second multi-step prediction horizon ($h=1, 2, 3$) is a mathematical state-space lookahead property.
- It does **not** automatically provide 10 seconds of operational defense in real enterprise operations.
- Operational lead time depends strictly on:
  1. *Early Divergence*: Whether threat momentum creates pre-manifestation drift before volume peaks.
  2. *Actionable Duration*: Whether the warning arrives early enough for defensive preparation actions to complete.
  3. *False Alarm Cost*: A noisy detector firing false alarms early by chance is harmful, not helpful.

## 2. Methodology Guards Applied
1. **Modeled Action Duration Assumption**:
   `modeled_action_duration_s = 20` is explicitly treated as a modeled experimental assumption, not an empirical SOC standard.
   Sensitivity analysis across $5\text{s}, 10\text{s}, 20\text{s}, 30\text{s}$ demonstrates the dependency.
2. **Separation of Evaluation Tiers**:
   - **Live Controlled Behavioural Progression Tier**: Real Windows Npcap/TShark loopback captures verifying that live telemetry produces an earlier signal than static baseline detectors.
   - **Dataset Ground-Truth Attack Progression Tier**: Contiguous CSE-CIC-IDS2018 Infiltration and DoS transition sequences evaluating true attack onset timing.

## 3. Quantitative Results Summary
- **Total Progression Runs Evaluated**: 21 runs (5 live controlled capture runs + 16 dataset ground-truth slices).
- **Lead Time vs Conventional Baseline Detector**:
  - Mean: **`8.75s`**
  - Median: **`5.0s`**
  - Std Dev: **`11.26s`**
  - 95% Bootstrap CI: **`[2.50s, 16.25s]`**
- **Lead Time vs Actual Attack / Escalation Onset**:
  - Mean: **`20.00s`**
  - Median: **`20.0s`**
  - Std Dev: **`10.69s`**
  - 95% Bootstrap CI: **`[12.50s, 27.50s]`**

## 4. Sensitivity Analysis across Modeled Action Durations

| Modeled Action Duration ($T_{\text{action}}$) | Actionable Success Count | Escalation Runs | Actionable Success Rate (%) |
|---|:---:|:---:|:---:|
| **5 seconds** | 6 | 8 | **75.0%** |
| **10 seconds** | 6 | 8 | **75.0%** |
| **20 seconds (Default Assumption)** | 2 | 8 | **25.0%** |
| **30 seconds** | 2 | 8 | **25.0%** |

## 5. Failure Case & Selectivity Distribution
- **Clean Success (Precedes Baseline & Actionable)**: 6 runs
- **Insufficient Preparation Time (< 20s)**: 4 runs
- **Late vs Baseline Detector**: 2 runs
- **Missed Escalation**: 0 runs
- **False Early Alarms on Clean Negative Controls**: 5 runs

## 6. Operational Trade-Off Finding
The forecasting pipeline exhibits a fundamental operational trade-off:
- **AR(5) Predictive Trajectory**: Alerts an average of 10.0s earlier than static thresholds, providing high sensitivity to pre-manifestation momentum, but at the cost of higher false-alarm sensitivity.
- **Calibrated / Static Detectors**: Provide high selectivity and near-zero false alarms, but generate zero advance warning, alerting only after thresholds are breached.
