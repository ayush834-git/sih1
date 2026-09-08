# SIH 26153 — Authoritative Final Evidence Guide & Metric Provenance

**Problem Statement ID:** SIH 26153  
**Project:** Predictive Cyber Defense: AI-Based Network Attack Forecasting & Behavioral Security Decision Layer  
**Target Standard:** A+ Research & Epistemic Rigor  
**Status:** Authoritative & Frozen  

---

## 1. Executive Metric Provenance Index

This section answers the fundamental scientific audit question: **"Where did this exact number come from?"** for every metric eligible for presentation in the README, UI, demo video, presentation slides, or judging defense.

```
+-------------------------------------------------------------------------------------------------------------------------+
|                                           METRIC AUDIT & PROVENANCE MAP                                                 |
+------------------------------------+-----------+-----------------------------------+------------------------------------+
| Metric Name                        | Value     | Source Artifact                   | Primary Methodology / Scope        |
+------------------------------------+-----------+-----------------------------------+------------------------------------+
| 10s Discretized NetworkStates      | 8,640     | artifacts/state_sequences/        | 48h contiguous capture (2x 24h)    |
| Clean Retained Flow Telemetry      | 931,136   | artifacts/state_sequences/        | Deduplicated CICFlowMeter NetFlow  |
| Empty 10s Window Bins              | 1,827     | artifacts/state_sequences/        | 21.15% sparsity (explicit gaps)    |
| AR(5) 1-Step Directional Accuracy  | 68.10%    | delta_baseline_v2/                | Linear autoregression on 15 deltas |
| AR(5) Median Normalized MAE        | 0.4052    | delta_baseline_v2/                | IQR scale-normalized error         |
| AR(5) vs AR(3) Accuracy Gain       | +1.84%    | ar_order_availability_v1/         | 68.64% vs 66.80% on test split     |
| AR(5) Infiltration Forecast Loss   | 0         | ar_order_availability_v1/         | 0 lost across all 4 attack blocks  |
| True Open-Loop Accuracy (h=1/2/3)  | 68/51/50% | delta_rollout_uncertainty_v1_cor/ | Unrefreshed recursive rollout      |
| Receding Horizon Rolling Refresh   | 68.11%    | delta_rollout_uncertainty_v1_cor/ | Observation-refreshed 1-step       |
| 90% Nominal Bootstrap Coverage     | 89.71%    | delta_rollout_uncertainty_v1_cor/ | Training residual pool bootstrap   |
| Anti-Stage-Collapse Pass Rate      | 100%      | security_bridge_validation_v1/    | 5 distinct stages across 6 fixtures|
| Decision Layer Safety Invariants   | 13 / 13   | decision_layer_v1/                | 100% human-gated reversibility     |
| Controlled Raw Alert Lead Time     | 10.0s     | response_window_v1/               | w=4 (40s) vs w=5 (50s) alert       |
| Useful Response-Window Gain        | 10.0s     | response_window_v1/               | 20s action completes pre-onset     |
| Noise False Positives              | 0         | response_window_v1/               | Benign bursts & ambiguous noise    |
| Explainability Perturbation Shift  | +0.30–0.85| explainability_v1/                | Signed AR lag decomposition        |
+------------------------------------+-----------+-----------------------------------+------------------------------------+
```

---

## 2. Granular Metric Provenance Dossiers

### M01–M03: Telemetry State Volumes (8,640 States)
- **Authoritative Values:** 
  - Wednesday 10s states: **`4,320`**
  - Thursday 10s states: **`4,320`**
  - Total states: **`8,640`** ($172,800$ telemetry seconds)
- **Source Artifact:** `artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.manifest.json` and `Thursday-01-03-2018_TrafficForML_CICFlowMeter.manifest.json`
- **Methodology:** 10-second non-overlapping fixed time-window aggregation across two 24-hour CSE-CIC-IDS2018 captures.
- **Caveat:** Day-first timestamps parsed strictly; timezone-naive representation preserved.
- **Presentation Wording:** *"Evaluated across 8,640 contiguous 10-second network state vectors spanning 48 hours of enterprise NetFlow telemetry."*

---

### M04–M06: Retained Flow Records (931,136 Flows)
- **Authoritative Values:**
  - Wednesday clean flows: **`600,245`** (from `613,104` raw rows; 33 repeated headers and 12,826 duplicate flows removed)
  - Thursday clean flows: **`330,891`** (from `331,125` raw rows; 25 repeated headers and 209 duplicate flows removed)
  - Total clean flows: **`931,136`** (from `944,229` total raw rows)
- **Source Artifact:** `artifacts/state_sequences/` manifests (field `cleaning.rows_retained`)
- **Methodology:** Strict header validation, day-first timestamp parsing, duplicate row deduplication, and NaN/Inf mapping to explicit missingness without whole-row drops.
- **Caveat:** 6 host endpoint topology features are unobservable in 80-column CSV flow exports and strictly marked `UNAVAILABLE`.
- **Presentation Wording:** *"Processed 931,136 clean flow records following strict deduplication and RFC-compliant missingness isolation."*

---

### M07–M09: Window Sparsity & Empty Windows (1,827 Empty Windows)
- **Authoritative Values:**
  - Wednesday empty windows: **`914`** ($21.16\%$)
  - Thursday empty windows: **`913`** ($21.13\%$)
  - Total empty windows: **`1,827`** ($21.15\%$)
- **Source Artifact:** `artifacts/state_sequences/` manifests (field `empty_window_count`)
- **Methodology:** Windows with 0 flow records are explicitly flagged with `is_empty = True`.
- **Caveat:** State transitions are never constructed across empty windows or session gaps.
- **Presentation Wording:** *"Accurately models real-world traffic intermittency (21.15% empty windows) with zero cross-gap transition interpolation."*

---

### M10–M15: Baseline Ladder & Autoregressive Dynamics (AR(5) = 68.10% DA)
- **Authoritative Values:**
  - B1 ZeroChange: **`2.11%`** DA, Median Norm MAE `0.4325`
  - B2 Persistence: **`32.89%`** DA, Median Norm MAE `0.8000`
  - B3 EWMA ($\alpha=0.1$): **`30.22%`** DA, Median Norm MAE `0.5212`
  - **B4 AR(5) (Primary Dynamics): `68.10%` DA, Median Norm MAE `0.4052`**
  - B5 Ridge ($L_2$ Regularized): **`65.91%`** DA, Median Norm MAE `0.5081`
  - B6 GBDT (Histogram Trees): **`64.49%`** DA, Median Norm MAE `0.5253`
- **Source Artifact:** `artifacts/experiments/delta_baseline_v2/comparison_table.csv` and `results_summary.json`
- **Methodology:** 60/15/25 chronological temporal train/val/test split ($N_{\text{test}}=1,682$ transitions). Targets normalized via training interquartile range ($s_j = \text{IQR}(y_{\text{train}, j})$).
- **Caveat:** Evaluates 10-second forward delta direction ($\text{sign}(\Delta \hat{S}) == \text{sign}(\Delta S)$); not a static flow classification metric.
- **Presentation Wording:** *"AR(5) achieves 68.10% directional accuracy on unseen temporal splits, outperforming persistence baselines (32.89%) and matching or exceeding complex gradient boosted trees (64.49%) with minimal compute overhead."*

---

### M16–M20: AR(5) vs AR(3) Trade-Off Audit (+1.84% Gain, 0 Attack Forecasts Lost)
- **Authoritative Values:**
  - AR(3) Test Directional Accuracy: **`66.80%`**
  - AR(5) Test Directional Accuracy: **`68.64%`**
  - Directional Accuracy Gain: **`+1.84%`** (`0.018429...`)
  - Overall Availability Loss Rate: **`0.29%`** (only 25 valid state forecasts lost out of 8,640)
  - Attack Block Forecasts Lost: **`0`** across all 4 observed infiltration periods (1,708 valid forecasts preserved)
- **Source Artifact:** `artifacts/experiments/ar_order_availability_v1/results_summary.json` and `block_comparison.csv`
- **Methodology:** Full 8,640-state replay comparing 3-delta ($h=4$) vs 5-delta ($h=6$) history requirements across contiguous state streams.
- **Caveat:** AR(5) requires 6 consecutive states for cold-start warmup (50s); warmups occur during baseline before attack onset.
- **Presentation Wording:** *"Retaining AR(5) delivers a +1.84% accuracy advantage over AR(3) while incurring zero forecast loss during active attack operations."*

---

### M21–M26: Forecast Horizon Boundaries (Open-Loop vs Receding Horizon)
- **Authoritative Values:**
  - True Open-Loop Recursive: $h=1$ (10s) = **`68.09%`**, $h=2$ (20s) = **`50.95%`**, $h=3$ (30s) = **`50.21%`**
  - Rolling Observation-Refreshed: $h=1$ = **`68.09%`**, $h=2$ = **`68.09%`**, $h=3$ = **`68.11%`**
- **Source Artifact:** `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/horizon_metrics.csv`
- **Methodology:** Evaluating recursive autoregression without intermediate observations vs 1-step forecasting with observation refresh ($N=1,676$).
- **Caveat:** Unrefreshed multi-step forecasting compounds error toward random walk within 20–30 seconds.
- **Presentation Wording:** *"Predictive utility operates on a receding horizon: while unrefreshed open-loop forecasting degrades by 30 seconds, continuously refreshing with arriving telemetry sustains ~68.1% directional accuracy."*

---

### M27–M29: Uncertainty Quantification & Interval Coverage (89.71% Observed at 90% Nominal)
- **Authoritative Values:**
  - 80% Nominal Coverage $\to$ Observed: **`81.92%`** (Error: $+1.92\%$)
  - 90% Nominal Coverage $\to$ Observed: **`89.71%`** (Error: **`-0.29%`**)
  - 95% Nominal Coverage $\to$ Observed: **`93.85%`** (Error: $-1.15\%$)
- **Source Artifact:** `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/coverage.csv`
- **Methodology:** Non-parametric empirical residual bootstrap pool constructed strictly from training predictions; evaluated against unseen test split.
- **Caveat:** Represents marginal per-feature intervals, not a joint multidimensional Bayesian posterior.
- **Presentation Wording:** *"Training-only empirical residual bootstrap yields calibrated prediction intervals with only 0.29% coverage error at the 90% nominal confidence level."*

---

### M30–M31: Security Discrimination & Decision Safety (100% Anti-Collapse, 13/13 Safety Rules)
- **Authoritative Values:**
  - Anti-Stage Collapse Pass Rate: **`100%`** (5 distinct primary stages across 6 fixtures)
  - Decision Layer Safety Invariants Passed: **`13 / 13`** ($100\%$)
  - Human Approval Gating: **`100%`**
  - Automated Destructive Execution: **`0%`**
  - Duplicate Alert Suppression: **`100%`**
- **Source Artifact:** `artifacts/experiments/security_bridge_validation_v1/` and `artifacts/experiments/decision_layer_v1/`
- **Methodology:** Evaluation across canonical behavioral fixtures and 7 operational decision scenarios.
- **Caveat:** ATT&CK technique IDs (T1046, T1498, T1048, T1071) provide structured explanatory context rather than hard ML labels.
- **Presentation Wording:** *"The decision layer strictly enforces 13 safety invariants: 100% human approval gating, zero automated destructive actions, role-differentiated routing, and clean UNKNOWN abstention on benign traffic."*

---

### M32–M34: Explainability & Perturbation Responses (+0.30 to +0.85 Confidence Shifts)
- **Authoritative Values:**
  - Reconnaissance Perturbation (`dst_port_diversity` $+5 \to +25$): Shift = **`+0.30`** ($0.55 \to 0.85$, $\text{INCREASING}$)
  - Impact / DoS Perturbation (`flow_count + rst_ratio` $+50/0.05 \to +500/0.45$): Shift = **`+0.85`** ($0.00 \to 0.85$, $\text{INCREASING}$)
  - Collection / Exfiltration Perturbation (`byte_rate + pkt_size_mean` $+5\text{k}/100 \to +250\text{k}/600$): Shift = **`+0.80`** ($0.00 \to 0.80$, $\text{INCREASING}$)
  - Deterministic Idempotence: **`PASS`** (100% bitwise identical)
- **Source Artifact:** `artifacts/experiments/explainability_v1/perturbation_results.csv` and `explanation_consistency.csv`
- **Methodology:** Exact mathematical signed lag decomposition ($\beta_{j, l} \cdot \Delta x_{j, t-l+1}$) normalized by training IQR.
- **Caveat:** Explanations represent statistical feature contributions, not causal or payload-level proofs.
- **Presentation Wording:** *"Forecast explanations are derived from exact autoregressive coefficient decomposition and scale-normalized feature distributions, providing transparent, non-hallucinatory evidence."*

---

### M35–M37: Response Window Gain & False Alarm Selectivity (10.0s Lead Time, 0 FP)
- **Authoritative Values:**
  - Average Raw Lead Time: **`10.0s`** (Predictive alert at $w=4$ / 40s vs Current-State at $w=5$ / 50s)
  - Simulated Action Duration: **`20.0s`**
  - Simulated Useful Response-Window Gain: **`10.0s`** (Defender B completes at 60s pre-onset; Defender A completes at 70s post-onset)
  - False Positives on Benign Burst & Ambiguous Noise: **`0`**
- **Source Artifact:** `artifacts/experiments/response_window_v1/results_summary.json` and `fairness_results.csv`
- **Methodology:** Controlled deterministic replay across 5 standardized scenarios with frozen sustained event definitions ($E$).
- **Caveat:** Action durations are simulated in controlled replay; does NOT measure live human SOC analyst cognitive triage latency.
- **Presentation Wording:** *"Under controlled progression replays, predictive trajectory forecasting triggered an alert 10.0 seconds earlier than current-state thresholding, enabling a modeled 20-second preparation action to complete prior to sustained event onset without generating false alarms on noise."*

---

## 3. Unified Baseline Consistency & Model Comparison Table (Part E)

To maintain absolute scientific integrity, models evaluating continuous delta-state forecasting must NOT be conflated with models evaluating binary attack classification. The table below explicitly separates these tasks:

```
+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
|                                                    UNIFIED MODEL EVALUATION & BASELINE COMPARISON TABLE                                                       |
+---------------------+-------------------------------+-------------------------+-------------------+----------------+-------------+---------+------------------+
| Model               | Task / Objective              | Feature Inputs          | Target Formulation| Temporal Split | Metric      | Result  | N Samples| Key Limitations  |
+---------------------+-------------------------------+-------------------------+-------------------+----------------+-------------+---------+------------------+
| B1 ZeroChange       | Delta-State Forecasting       | None                    | Delta_S(t+1) = 0  | Chrono Test 25%| Dir Acc (DA)| 2.11%   | 1,682   | Naive zero delta |
| B2 Persistence      | Delta-State Forecasting       | 1 Lag Delta (15 feats)  | Delta_S(t)        | Chrono Test 25%| Dir Acc (DA)| 32.89%  | 1,682   | Single-step lag  |
| B3 EWMA (alpha=0.1) | Delta-State Forecasting       | Historical Deltas       | Smoothed Delta_S  | Chrono Test 25%| Dir Acc (DA)| 30.22%  | 1,682   | Exponential decay|
| B4 AR(3) Linear     | Delta-State Forecasting       | 3 Lag Deltas (h=4)      | Per-feature delta | Chrono Test 25%| Dir Acc (DA)| 66.80%  | 1,682   | 3-lag history    |
| B4 AR(5) Linear     | Delta-State Forecasting       | 5 Lag Deltas (h=6)      | Per-feature delta | Chrono Test 25%| Dir Acc (DA)| 68.10%  | 1,682   | Primary dynamics |
| B5 Ridge Regression | Delta-State Forecasting       | Scaled History [S(t-4).]| Vectorized delta  | Chrono Test 25%| Dir Acc (DA)| 65.91%  | 1,682   | L2 linear model  |
| B6 GBDT Regressor   | Delta-State Forecasting       | Scaled History [S(t-4).]| Per-feature delta | Chrono Test 25%| Dir Acc (DA)| 64.49%  | 1,682   | HistGradientTree |
| Logistic Regression | Supervised Event Detection    | Current State S(t)      | Binary Event (0/1)| Controlled S01 | Window Alert| w=6 (0s)| 8 windows| Overfits burst   |
+---------------------+-------------------------------+-------------------------+-------------------+----------------+-------------+---------+------------------+
```

### Key Methodological Distinctions:
1. **Delta Dynamics (B1–B6):** Evaluate multi-feature numerical trajectory forecasting ($\Delta S_t \in \mathbb{R}^{15}$). Evaluated using scale-normalized Directional Accuracy and Normalized MAE.
2. **Supervised Logistic Classifier:** Evaluates static threshold crossing for binary event presence ($P(\text{Event} \mid S_t) \ge 0.5$). It alerted at $w=6$ on reconnaissance, fired premature false alarms ($w=0$) on benign bursts, and cannot forecast future trajectories.

---

## 4. Response-Window Audit & Experimental Verification (Part F)

Re-audit of `response_window_v1` confirms strict compliance with the following 8 experimental controls:

1. **Common Event Definition:** Objective sustained condition $E$ applied identically across all models:
   - *Reconnaissance:* $\text{dst\_port\_diversity} \ge 20$ for $\ge 2$ consecutive 10s windows.
   - *Impact / DoS:* $\text{flow\_count} \ge 200 \land \text{rst\_ratio} \ge 0.25$ for $\ge 2$ consecutive 10s windows.
   - *Collection / Exfiltration:* $\text{byte\_rate} \ge 100,000\text{ B/s}$ for $\ge 2$ consecutive 10s windows.
2. **Common Baseline:** Conventional Current-State Detector triggers strictly upon the first observed state crossing the threshold ($w=5$).
3. **No Ground-Truth Leakage:** Telemetry enters exclusively through schema-validated `NetworkState` instances with zero label attributes.
4. **Identical Simulated Action Duration:** Preparation actions (`REVIEW_BOUNDARY_ACLS`, `PREPARE_RATE_LIMIT`, `PREPARE_EGRESS_RESTRICTION`) are assigned identical 20-second execution durations across Defender A and Defender B.
5. **Valid Predictive Alert:** Predictive Trajectory Detector alerted at $w=4$ (40s), projecting forward delta momentum crossing the threshold at $w=5$.
6. **Valid Baseline Alert:** Conventional detector alerted at $w=5$ (50s), upon observing the initial elevation.
7. **No False-Positive Inflation:** Both Predictive and Conventional baseline detectors generated exactly **`0` false alarms** on benign burst traffic and ambiguous background noise.
8. **Exact Attack Scenario Count:** Exactly 3 canonical progression scenarios evaluated (`1_recon_progression`, `2_dos_progression`, `3_exfiltration_progression`) alongside 2 negative control scenarios (`4_benign_burst_traffic`, `5_ambiguous_mixed_traffic`).

> [!IMPORTANT]
> **Explicit Scope Statement:** This is a **controlled simulated useful-response-window result**. It demonstrates that 10-second earlier alert delivery enables a modeled 20-second preparation action to complete prior to sustained event onset. It must NOT be converted into an empirical claim regarding live human SOC analyst response latency.

---

## 5. CICFlowMeter Timestamp Provenance & Dataset Integrity (Part G)

The repository preserves the complete, auditable provenance of the CSE-CIC-IDS2018 benchmark dataset:

- **Raw Source Files:**
  - `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` (SHA-256: `f15e2a12...`)
  - `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` (SHA-256: `b0534c5d...`)
- **Parser Format:** Python `dateutil.parser` with `dayfirst=True` strictly matching the DD/MM/YYYY CSV format.
- **Clock Format & Infiltration Alignment:**
  - Infiltration attack executions in CSE-CIC-IDS2018 occurred during the afternoon schedule.
  - The CICFlowMeter tool exported timestamps in a 12-hour clock format without AM/PM markers (e.g., `01:42` corresponds to 13:42 / 1:42 PM UTC).
  - The pipeline observes four contiguous infiltration-active blocks:
    - *Block 1 (Wed):* 01:42 $\to$ 02:39 (343 states)
    - *Block 2 (Wed):* 10:50 $\to$ 12:04 (445 states)
    - *Block 3 (Thu):* 02:00 $\to$ 03:36 (577 states)
    - *Block 4 (Thu):* 09:57 $\to$ 10:54 (343 states)
- **Why No Synthetic Timestamp Shifting Is Performed:**
  - The pipeline treats timestamps as timezone-naive, exactly as emitted by the authoritative source dataset.
  - No synthetic 12-hour offsets or artificial time adjustments are applied, ensuring 100% verifiable alignment with the raw CSV files.

---

## 6. Reproducibility & Execution Commands (Part H)

The entire evidence stack is fully reproducible using standard Python commands without specialized hardware or root privileges:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run full test suite with verbose reporting (117+ tests)
python -m unittest discover -s tests -v

# 3. Run pytest runner
python -m pytest

# 4. Execute live canonical demo replay in non-blocking mode
python -m scenarios.demo.run_demo --no-sleep
```

All referenced artifact paths in `artifacts/final_validation/`, `artifacts/experiments/`, and `artifacts/state_sequences/` are committed and bitwise immutable.
