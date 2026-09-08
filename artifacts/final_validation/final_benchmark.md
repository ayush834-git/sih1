# SIH 26153 — Final Consolidated Benchmark Report

---

## 1. Executive Summary & Epistemic Boundaries

This document serves as the authoritative, judge-facing benchmark consolidation for **SIH 26153: Predictive Cyber Defense**.

### Mandatory Task Separation
In evaluation of predictive cyber defense systems, metrics across fundamentally distinct machine learning tasks must **never be collapsed into a single artificial ranking**:
1. **Delta-State Regression Task:** Predicts the continuous 10-second forward transition vector $\Delta S_{t+1} = S_{t+1} - S_t \in \mathbb{R}^{15}$. Evaluated via **Directional Accuracy (DA)** and **Scale-Normalized Median MAE**.
2. **Supervised Attack Classification Task:** Predicts a binary label or threshold crossing on current/future states. Evaluated via **Lead Time (seconds)**, **Alert Precision/Recall**, and **False Positive Rate (FPR)**.

---

## 2. Benchmark Table 1 — Delta-State Forecasting Performance

Evaluated on the frozen 25% chronological test split ($N = 1,682$ contiguous 10-second state transitions, $25,230$ individual feature predictions across 15 transport dimensions):

| Model Ladder | Task / Target | Context Required | Test DA | 95% MBB CI | Median Norm MAE | Norm RMSE | Availability | Source Artifact |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **B1: ZeroChange** | $\Delta S_{t+1} = 0$ | 0 deltas | **`2.11%`** | — | `0.4325` | `8,482.14` | 100.0% | `delta_baseline_v2` |
| **B2: Persistence** | $\Delta S_{t+1} = \Delta S_t$ | 1 delta | **`32.89%`** | — | `0.8000` | `13,583.83` | 78.15% | `delta_baseline_v2` |
| **B3: EWMA ($\alpha=0.1$)** | Exponential Smoothing | 5 deltas | **`30.22%`** | — | `0.5212` | `9,686.01` | 78.15% | `delta_baseline_v2` |
| **B4: AR(3) Baseline** | Per-feature AR($p=3$) | 3 deltas | **`67.28%`** | $[66.49\%, 68.07\%]$ | `0.4073` | `8,285.34` | **`78.15%`** | `delta_baseline_v2` |
| **B4: AR(5) Primary** | Per-feature AR($p=5$) | 5 deltas | **`68.10%`** | **`[67.32%, 68.87%]`** | **`0.4052`** | **`8,201.93`** | **`77.86%`** | `delta_baseline_v2` |
| **B5: Ridge Regression** | L2 Regularized Linear | 5 deltas | **`65.91%`** | — | `0.5081` | `9,292.69` | 77.86% | `delta_baseline_v2` |
| **B6: GBDT Regressor** | HistGradientBoosting | 5 deltas | **`64.49%`** | — | `0.5253` | `9,129.57` | 77.86% | `delta_baseline_v2` |

**Key Findings:**
- **Predictive Physics:** AR(5) significantly outperforms naive baselines ($68.10\%$ vs $2.11\%$ for ZeroChange and $32.89\%$ for Persistence).
- **Efficiency & Robustness:** AR(5) delivers lower Median Normalized MAE ($0.4052$) and higher DA than regularized multi-feature Ridge ($65.91\%$) and nonlinear GBDT ($64.49\%$).

---

## 3. Benchmark Table 2 — Supervised Classification & Event Detection

Evaluated across 5 standardized controlled replay scenarios ($40$ total 10-second windows: 3 attack progressions, 1 benign burst, 1 ambiguous noise):

| Detection Architecture | Task Type | Attack Alert Window | Raw Lead Time | Simulated Useful Prep Gain | Benign False Alarms | Noise False Alarms | Precision / Recall | Source Artifact |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Logistic Regression** | Supervised Static Binary | $w=0$ (premature) | Invalid (Fails on baseline) | None ($0.0\text{s}$) | $0/8$ | **`8/8 (100% FA)`** | Low ($0.50 / 0.67$) | `response_window_v1` |
| **Conventional Detector** | Current Threshold Crossing | $w=5$ ($50\text{s}$) | $10.0\text{s}$ before sustained | Late ($-10.0\text{s}$ post-onset) | **`0/8`** | **`0/8`** | **`1.00 / 1.00`** | `response_window_v1` |
| **Predictive Detector** | Trajectory Projection (AR5) | **`w=4 (40s)`** | **`20.0s`** before sustained | **`+10.0s useful gain`** | **`0/8`** | **`0/8`** | **`1.00 / 1.00`** | `response_window_v1` |

**Important Distinction:**
- Supervised Logistic Regression fits training decision boundaries on raw values; in dynamic replay, it triggers prematurely on normal baseline traffic ($w=0$), completely misses sustained exfiltration surges, and suffers a $100\%$ false positive rate on ambiguous noise.
- The Predictive Trajectory Detector achieves **zero false alarms** on benign/noise traffic while providing **10.0s earlier preparation window** over conventional threshold crossing.

---

## 4. Benchmark Table 3 — AR(5) vs AR(3) Trade-Off Summary

| Comparison Dimension | AR(3) | AR(5) | Paired Difference / Effect | Statistical Significance |
| :--- | :---: | :---: | :---: | :--- |
| **Aligned Test Directional Accuracy** | $67.28\%$ | **`68.10%`** | **`+0.82 pp`** ($[+0.23\%, +1.38\%]$) | McNemar $\chi^2 = 13.24$, $p = 2.74 \times 10^{-4}$ |
| **Global Dataset Directional Accuracy** | $66.80\%$ | **`68.64%`** | **`+1.84 pp`** ($[+1.28\%, +2.41\%]$) | McNemar $\chi^2 = 106.18$, $p < 10^{-15}$ |
| **Global Forecast Availability** | **`78.15%`** ($6,752$) | **`77.86%`** ($6,727$) | **`-0.29%`** ($25$ states lost) | Negligible operational impact |
| **Attack Block Forecast Retention** | **`100.0%`** ($1,708$) | **`100.0%`** ($1,708$) | **`0 states lost in attacks`** | Identical availability in active attacks |
| **Infiltration Block Mean DA Gain** | — | — | **`+1.69 pp`** ($[+0.91\%, +2.16\%]$) | AR(5) wins in 4/4 observed folds |

**Policy Decision (Recommendation C):**
AR(5) is retained as the primary dynamics core due to superior accuracy and zero availability loss in attack windows, with an automated architectural fallback to AR(3) when 5 historical deltas are unavailable.

---

## 5. Benchmark Table 4 — Response Window & Safety Invariants

| Domain | Validated Metric | Exact Scientific Qualification |
| :--- | :---: | :--- |
| **Raw Lead Time** | **`10.0s`** | Predictive alert triggers 1 full 10-second window prior to current-state threshold crossings. |
| **Simulated Useful Prep Gain** | **`+10.0s`** | Modeled 20s reversible preparation action completes at $60\text{s}$ (prior to sustained event onset at $60\text{s}$), whereas conventional detector finishes at $70\text{s}$ ($10\text{s}$ late). |
| **Attack Scenarios Tested** | **`3 / 3`** | Evaluated on Reconnaissance, DoS, and Exfiltration progression sequences. |
| **Decision Safety Invariants** | **`13 / 13 (100%)`** | 100% of recommendations enforce `requires_human=True` and `is_reversible=True`. |
| **Autonomous Destructive Execution** | **`0%`** | The system possesses zero interface or authority to perform autonomous destructive network actions. |
| **Repository Test Pass Rate** | **`151 / 151 (100%)`** | Full test suite passes cleanly with zero regressions across Days 1 through 10. |
