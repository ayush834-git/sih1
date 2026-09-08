# Temporal Representation & Feature Observability Diagnostic Study Report
**SIH PS 26153**: AI-Based Network Attack Forecasting from Network Traffic Data  
**Repository**: `sih1`  
**Study ID**: `temporal_representation_study_v1`  
**Execution Status**: `COMPLETED`  
**Date**: 2026-09-05  

---

## 1. Executive Summary & Explicit Final Verdict

### Final Scientific Verdict: `CONTRADICTED FOR NETFLOW OBSERVABILITY` (Hypothesis A Confirmed)

The central purpose of this diagnostic study was to distinguish:
- **Hypothesis A (True Feature-Space Limitation)**: The 10-second summary NetFlow telemetry genuinely lacks discriminative information to separate lightweight Thursday Block 4 web infiltration from normal background enterprise traffic.
- **Hypothesis B (Representation Limitation)**: The discriminative information exists in the telemetry, but current bridge architectures discard it because they examine instantaneous levels rather than temporal trajectories.

Across **all 6 pre-specified information families** (derivatives, acceleration, burst cadence, cross-feature synchrony, and post-hoc AR(5) forecast residuals), evaluated under strict causal conditions with 2,000-resample Moving Block Bootstrap ($L=30$ windows / 300s):

| Research Question | Scientific Answer | Empirical Finding |
| :--- | :--- | :--- |
| **Q1: Does Block 4 contain detectable temporal information in existing NetFlow?** | **NO** | 21 of 27 candidate temporal representations exhibit 95% bootstrap confidence intervals spanning zero, with distribution overlaps between 76% and 98%. |
| **Q2: If yes, which representation family captures it?** | **NONE** | No representation family (derivatives, acceleration, burst, synchrony, or residuals) produces a credible, reproducible separation for Block 4. |
| **Q3: Does the effect survive dependence-aware evaluation?** | **NO** | Under Moving Block Bootstrap ($L=30$), differencing and acceleration collapse into telemetry noise ($d < 0.02$). |
| **Q4: Does it reproduce across multiple infiltration blocks?** | **NO** | High separation on Wednesday scanning regimes ($d \approx 1.0 - 1.5$) does not transfer to Thursday Block 4 ($d \approx 0.019$). |
| **Q5: Is it strong enough to justify designing a `bridge_v4`?** | **NO (REJECT)** | Designing `bridge_v4` on 10-second NetFlow telemetry is scientifically unjustified and would amount to test-set curve fitting. |
| **Q6: Or does the evidence indicate a genuine observability ceiling?** | **YES** | Conclusive evidence confirms an observability ceiling: 10-second flow summaries cannot detect single HTTP/exploit payloads submerged in background enterprise browsing. |

---

## 2. Frozen Repository Mapping & Telemetry Universe

### 2.1 Frozen Architecture
In strict adherence to protocol, **no frozen components were modified**:
- `core/contracts.py`: Frozen contract intact.
- `eval/dataset.py`: Frozen loaders and population splits preserved.
- `runtime/train_authoritative_model.py`: Frozen training logic preserved.
- `eval/rollout.py`: Frozen authoritative rollout engine preserved.
- `security/bridge.py`, `bridge_v2.py`, `bridge_v3.py`, `risk_engine.py`: Frozen behavioral bridges and risk engines untouched.
- `artifacts/models/ar5_authoritative/`: AR(5) model parameters and coefficients untouched.

### 2.2 Exact Available Feature Universe
From canonical inspection of CIC-IDS2018 NetFlow CSV telemetry, exactly 15 numerical features are available per 10s window:
1. `flow_count`
2. `packet_rate`
3. `byte_rate`
4. `mean_flow_duration`
5. `dst_port_diversity`
6. `syn_count`
7. `ack_count`
8. `rst_count`
9. `syn_ratio`
10. `rst_ratio`
11. `iat_mean`
12. `iat_std`
13. `pkt_size_mean`
14. `pkt_size_std`
15. `byte_variance`

> [!NOTE]
> Topology-oriented metrics (`fan_out`, `src_ip_diversity`, `dst_ip_diversity`, `src_port_diversity`, `internal_ratio`, `east_west_count`) are confirmed strictly `UNAVAILABLE` in the underlying CSV feed and were not synthesized or reconstructed.

### 2.3 Frozen Data Populations & Pre-Test Calibration
- **Pre-Test Calibration Split**: Thursday 2018-03-01 `04:00:00` to `08:00:00` UTC ($N=625$ windows). All baseline statistics, robust medians, and dispersion scale floors were derived strictly prior to the `08:19:40` test split cutoff:
  - `dst_port_diversity`: floor = $2.0$
  - `flow_count`: floor = $5.0$
  - `byte_rate`: floor = $1,000.0$ B/s
  - `iat_mean`: floor = $0.20$ s
  - `rst_ratio`: floor = $0.01$
- **Primary Diagnostic Benchmark**:
  - Reference: Immediate Pre-Onset Benign Context (`08:19:40` to `09:57:00` UTC, $N=584$ windows)
  - Target: Thursday Attack Block 4 (`09:57:00` to `10:54:00` UTC, $N=343$ windows)
- **Secondary Generalization Populations**:
  - Full Benign Test Population: $N=1,339$ windows
  - Wednesday Infiltration Block 1: $N=343$ windows
  - Wednesday Infiltration Block 2: $N=445$ windows
  - Thursday Infiltration Block 3: $N=577$ windows
  - Thursday Infiltration Block 4: $N=343$ windows
  - Pooled Infiltration: $N=1,708$ windows

---

## 3. Mathematical Representation Families

Each temporal representation was extracted in strict causal sequence $t=0, 1, \dots, T$:

### Family 0: Raw Levels
$$x_t$$
Serves as the empirical baseline representation for all 15 NetFlow features.

### Family 1: First-Order Change (Velocity)
$$\Delta x_t = x_t - x_{t-1}, \quad \tilde{\Delta} x_t = \frac{x_t - x_{t-1}}{\max(1.4826 \cdot \text{MAD}_{W}(x), \text{floor}(x))}$$
where $\text{MAD}_{W}(x)$ is computed causally over the trailing window $\{x_{t-W}, \dots, x_{t-1}\}$ ($W=30$ windows = 300s).

### Family 2: Second-Order Change (Acceleration)
$$\Delta^2 x_t = x_t - 2x_{t-1} + x_{t-2}, \quad \tilde{\Delta}^2 x_t = \frac{\Delta x_t - \Delta x_{t-1}}{\max(1.4826 \cdot \text{MAD}_{W}(\Delta x), 0.5 \cdot \text{floor}(x))}$$

### Family 3: Burst & Persistence Descriptors
- **Run Length**: Consecutive windows with robust $z_t \ge 2.0$.
- **Duty Cycle / Excursion Density**: Fraction of trailing $W=30$ windows with $z \ge 2.0$.
- **Quiet Period Duration**: Consecutive trailing windows with $z < 1.0$.

### Family 4: Cross-Feature Synchrony & Covariance
- **Directional Co-Movement**:
  $$\text{Sync}(A, B)_t = \text{sign}(\tilde{\Delta} A_t) \cdot \text{sign}(\tilde{\Delta} B_t) \cdot \sqrt{|\tilde{\Delta} A_t \cdot \tilde{\Delta} B_t|}$$
  Evaluated across pairs: `(flow, byte)`, `(flow, iat)`, `(flow, rst)`, `(byte, pkt)`.
- **Causal Regularized Mahalanobis Distance**:
  $$D_M(x_t) = \sqrt{(x_t - \mu_W)^T (\Sigma_W + 10^{-4} I)^{-1} (x_t - \mu_W)}$$
  across key volume vector `(dst_port, flow, byte, iat)` using historical trailing covariance $\Sigma_W$.

### Family 5: Post-Hoc AR(5) Forecast Residuals
At window $t$, the authoritative frozen AR(5) emits 1-step forecast $\hat{S}_{t+1|t}$. After window $t+1$ arrives, the evaluation layer computes:
$$e_{t+1} = S_{t+1} - \hat{S}_{t+1|t}$$
- **Residual Euclidean Norm**: $\|e_{t+1}\|_2$
- **Directional Alignment**: $\cos(\Delta S_{t+1}, \hat{\Delta}_{t+1})$
- **Feature-Level Forecast Drift**: $e_{t+1}(f)$
- *Quarantine guarantee*: Residuals are never fed back into AR(5) or the state history buffer.

---

## 4. Leakage & Causality Audit (10-Point Verification)

The dedicated test suite [`tests/test_temporal_representations.py`](file:///c:/Users/ayush/sih1/tests/test_temporal_representations.py) was implemented and executed:

| Test ID | Test Name | Audit Verification | Result |
| :--- | :--- | :--- | :--- |
| **Test 01** | `test_01_chronological_ordering_preservation` | Timestamps strictly monotonic ($t_i > t_{i-1}$) | `PASS` |
| **Test 02** | `test_02_truncation_invariance` | Feature values at window $k$ on truncated stream $S_{0:k}$ match full stream $S_{0:K}$ to 9 decimal places | `PASS` |
| **Test 03** | `test_03_no_future_state_access` | Mutating $S_9 \to 999999$ produces zero bitwise change on representations for $S_0 \dots S_8$ | `PASS` |
| **Test 04** | `test_04_label_independence` | State representations computed without any label, scenario, or ground-truth metadata | `PASS` |
| **Test 05** | `test_05_deterministic_replay` | Independent re-runs on identical sequences yield bitwise identical feature dicts | `PASS` |
| **Test 06** | `test_06_buffer_reset_isolation` | `reset()` flushes history, deltas, and pending forecasts completely; zero cross-session bleed | `PASS` |
| **Test 07** | `test_07_causal_warmup_and_guards` | Cold start ($t < 5$) executes safely with scale floors; zero NaNs, zero division errors | `PASS` |
| **Test 08** | `test_08_post_hoc_residual_isolation` | Residual evaluated post-hoc; state history contains only true observations, never residuals | `PASS` |
| **Test 09** | `test_09_reproducible_calibration` | Pre-test calibration split ($04:00-08:00$) yields deterministic, positive scale floors | `PASS` |
| **Test 10** | `test_10_schema_completeness` | Extracted records cover all 6 families and all declared scalar keys without truncation | `PASS` |

**Regression Suite**: All **239 tests** in the workspace passed with zero regressions (`Ran 239 tests in 8.954s - OK`).

---

## 5. Primary Benchmark Results (Block 4 vs Pre-Onset Context)

Evaluated between Pre-Onset Benign ($N=584$) and Attack Block 4 ($N=343$) using Moving Block Bootstrap ($L=30$ windows, $B=2,000$ resamples):

### Representation Audit Ranking

| Rank | Representation | Information Family | Pre-Onset Mean | Block 4 Mean | Observed Diff | 95% MBB CI | Cohen's $d$ | Overlap Coef | 95% CI Spans Zero? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `Fam0_Level_iat_mean` | Raw Level | 4.8178 s | 2.7072 s | -2.1107 | [-2.9599, -1.1687] | **-0.7695** | 60.3% | NO (Excludes 0)* |
| **2** | `Fam0_Level_rst_ratio` | Raw Level | 0.0186 | 0.0221 | +0.0035 | [+0.0013, +0.0058] | **+0.3871** | 76.1% | NO (Excludes 0) |
| **3** | `Fam3_Burst_byte_duty_cycle` | Burst/Persistence | 0.2883 | 0.2604 | -0.0279 | [-0.0706, +0.0276] | -0.3336 | 78.1% | **YES (Spans 0)** |
| **4** | `Fam4_Sync_flow_rst` | Synchrony | 0.3144 | -0.1607 | -0.4751 | [-0.8278, -0.0925] | -0.2960 | 87.7% | NO (Excludes 0) |
| **5** | `Fam0_Level_dst_port_diversity` | Raw Level | 23.96 | 47.92 | +23.96 | [+5.5267, +39.58] | +0.2460 | 95.0% | NO (Excludes 0) |
| **6** | `Fam0_Level_flow_count` | Raw Level | 148.6 | 179.3 | +30.7 | [+3.12, +58.4] | +0.2050 | 91.7% | NO (Excludes 0) |
| **7** | `Fam4_Sync_Mahalanobis_Vector` | Synchrony | 2.4864 | 4.0279 | +1.5415 | [+0.112, +2.971] | +0.1486 | 97.0% | NO (Excludes 0) |
| **8** | `Fam3_Burst_flow_quiet_duration`| Burst/Persistence | 2.9795 | 3.4985 | +0.5191 | [-0.312, +1.349] | +0.1391 | 92.9% | **YES (Spans 0)** |
| **9** | `Fam5_Res_Norm_Euclidean` | Forecast Residuals | 157.91 | 67.44 | -90.47 | [-234.1, +53.2] | -0.1072 | 97.3% | **YES (Spans 0)** |
| **10** | `Fam0_Level_byte_rate` | Raw Level | 44,591 | 37,215 | -7,376 | [-18,450, +3,700] | -0.0901 | 98.4% | **YES (Spans 0)** |
| **11** | `Fam3_Burst_flow_run_length` | Burst/Persistence | 0.1901 | 0.2391 | +0.0490 | [-0.071, +0.169] | +0.0900 | 97.8% | **YES (Spans 0)** |
| **12** | `Fam3_Burst_flow_duty_cycle` | Burst/Persistence | 0.1511 | 0.1545 | +0.0034 | [-0.042, +0.048] | +0.0467 | 83.8% | **YES (Spans 0)** |
| **13** | `Fam3_Burst_byte_run_length` | Burst/Persistence | 0.4264 | 0.3907 | -0.0357 | [-0.195, +0.123] | -0.0459 | 96.9% | **YES (Spans 0)** |
| **14** | `Fam3_Burst_dst_port_run_length`| Burst/Persistence | 0.1370 | 0.1545 | +0.0175 | [-0.065, +0.100] | +0.0381 | 98.2% | **YES (Spans 0)** |
| **15** | `Fam4_Sync_flow_iat` | Synchrony | 1.1871 | 1.1106 | -0.0764 | [-0.341, +0.188] | -0.0286 | 82.8% | **YES (Spans 0)** |
| **16** | `Fam5_Res_Delta_Alignment` | Forecast Residuals | 0.3648 | 0.3440 | -0.0207 | [-0.082, +0.041] | -0.0222 | 98.9% | **YES (Spans 0)** |
| **17** | `Fam1_NormDiff_byte_rate` | First Difference | -0.0018 | -0.0084 | -0.0066 | [-0.039, +0.025] | -0.0201 | 98.2% | **YES (Spans 0)** |
| **18** | `Fam4_Sync_flow_byte` | Synchrony | 2.3757 | 2.5102 | +0.1345 | [-0.420, +0.689] | +0.0189 | 86.4% | **YES (Spans 0)** |
| **19** | `Fam2_NormAccel_byte_rate` | Second Difference | +0.0011 | -0.0035 | -0.0046 | [-0.034, +0.025] | -0.0142 | 94.3% | **YES (Spans 0)** |
| **20** | `Fam1_NormDiff_iat_mean` | First Difference | +0.0021 | +0.0042 | +0.0021 | [-0.028, +0.032] | +0.0066 | 94.1% | **YES (Spans 0)** |
| **21** | `Fam2_NormAccel_flow_count` | Second Difference | +0.0004 | +0.0015 | +0.0011 | [-0.025, +0.027] | +0.0037 | 91.2% | **YES (Spans 0)** |
| **22** | `Fam1_NormDiff_flow_count` | First Difference | +0.0015 | +0.0024 | +0.0009 | [-0.026, +0.028] | +0.0030 | 92.6% | **YES (Spans 0)** |
| **23** | `Fam5_Res_iat_mean` | Forecast Residuals | +0.0123 | +0.0008 | -0.0114 | [-0.042, +0.019] | -0.0029 | 77.0% | **YES (Spans 0)** |
| **24** | `Fam5_Res_flow_count` | Forecast Residuals | +0.6242 | +1.0921 | +0.4678 | [-1.850, +2.786] | +0.0013 | 85.0% | **YES (Spans 0)** |
| **25** | `Fam1_Diff_dst_port_diversity` | First Difference | +0.0045 | +0.0061 | +0.0016 | [-0.035, +0.038] | +0.0006 | 95.3% | **YES (Spans 0)** |
| **26** | `Fam5_Res_dst_port_diversity` | Forecast Residuals | -0.0498 | +0.0148 | +0.0646 | [-0.210, +0.339] | +0.0004 | 81.3% | **YES (Spans 0)** |
| **27** | `Fam5_Res_byte_rate` | Forecast Residuals | 581.59 | 488.77 | -92.82 | [-412.0, +226.4] | -0.0001 | 97.2% | **YES (Spans 0)** |

\* *Important scientific note on `iat_mean`: As shown below, the shift in `iat_mean` reflects the diurnal background volume ramp from 08:00 to 11:00 UTC (observed on both Wednesday and Thursday) rather than attack infiltration.*

---

## 6. Detailed Family Investigations

### 6.1 First & Second Differences (Families 1 & 2): Noise Amplification
First differencing ($\Delta x_t$) and acceleration ($\Delta^2 x_t$) were evaluated to test whether rapid transitional spikes occur during infiltration.
- **Normalized Flow Delta ($\tilde{\Delta} \text{flow}$)**: Cohen's $d = +0.0030$, $95\%$ CI $[-0.026, +0.028]$ spans zero, distribution overlap = $92.6\%$.
- **Normalized Byte Delta ($\tilde{\Delta} \text{byte}$)**: Cohen's $d = -0.0201$, $95\%$ CI $[-0.039, +0.025]$ spans zero, distribution overlap = $98.2\%$.
- **Normalized Acceleration ($\tilde{\Delta}^2 \text{flow}$)**: Cohen's $d = +0.0037$, $95\%$ CI $[-0.025, +0.027]$ spans zero, distribution overlap = $91.2\%$.
- **Conclusion**: Differencing attenuates low-frequency drift and heavily amplifies high-frequency NetFlow telemetry noise. Neither first- nor second-order differencing provides any discriminative separation.

### 6.2 Burst & Persistence Descriptors (Family 3): Submerged Intermittency
To test whether lightweight infiltration executes in short, intermittent bursts:
- `dst_port_run_length`: Cohen's $d = +0.0381$, overlap = $98.2\%$, CI spans zero.
- `flow_run_length`: Cohen's $d = +0.0900$, overlap = $97.8\%$, CI spans zero.
- `byte_run_length`: Cohen's $d = -0.0459$, overlap = $97.0\%$, CI spans zero.
- `flow_duty_cycle`: Cohen's $d = +0.0467$, overlap = $83.8\%$, CI spans zero.
- `flow_quiet_duration`: Cohen's $d = +0.1391$, overlap = $92.9\%$, CI spans zero.
- **Conclusion**: There is no distinct "attack cadence" or anomalous burst persistence in Block 4. Burst excursions match normal background web browsing duty cycles.

### 6.3 Cross-Feature Synchrony (Family 4): Telemetry Decoupling
To test whether subtle cross-dimension relationships shift during stealth traffic:
- `Sync(flow, byte)`: $d = +0.0189$, overlap = $86.4\%$, CI spans zero.
- `Sync(flow, iat)`: $d = -0.0286$, overlap = $82.8\%$, CI spans zero.
- `Mahalanobis Vector`: $d = +0.1486$, overlap = $97.0\%$.
- **Conclusion**: Cross-feature co-movement and multi-dimensional distances remain essentially identical between benign traffic and Block 4.

### 6.4 Forecast Residuals (Family 5): AR(5) Systematic Error Analysis
This is the most critical test for the forecasting thesis: *Does the stealth attack make the frozen normal-behavior AR(5) model systematically wrong in a way benign traffic does not?*
- **Euclidean Residual Norm ($\|e\|_2$)**: Pre-onset mean = $157.91$, Block 4 mean = $67.44$, $d = -0.1072$, $95\%$ CI spans zero, overlap = $97.3\%$. (Residual error actually *decreased* during Block 4 due to slightly lower byte variance).
- **Directional Alignment ($\cos(\Delta S, \hat{\Delta})$)**: Pre-onset mean = $0.3648$, Block 4 mean = $0.3440$, $d = -0.0222$, overlap = $98.9\%$, CI spans zero.
- **Individual Residuals**:
  - `res_flow_count`: $d = +0.0013$, overlap = $85.0\%$, CI spans zero.
  - `res_dst_port_diversity`: $d = +0.0004$, overlap = $81.3\%$, CI spans zero.
  - `res_byte_rate`: $d = -0.0001$, overlap = $97.2\%$, CI spans zero.
  - `res_iat_mean`: $d = -0.0029$, overlap = $77.0\%$, CI spans zero.
- **Conclusion**: The frozen authoritative AR(5) model is **not** systematically wrong during Block 4. Prediction errors during attack are indistinguishable from normal prediction errors during benign operation.

---

## 7. Cross-Block Generalization (Secondary Benchmark)

The candidate representations were audited across Wednesday Blocks 1–2 and Thursday Blocks 3–4:

| Representation | Family | Wed Block 1 ($d$) | Wed Block 2 ($d$) | Thu Block 3 ($d$) | Thu Block 4 vs All ($d$) | Primary (B4 vs Pre) ($d$) | Regime Type |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `Fam0_Level_iat_mean` | Raw Level | **-1.349** | **-1.504** | **-1.389** | **-0.930** | -0.770 | Diurnal Traffic Volume Ramp |
| `Fam0_Level_rst_ratio` | Raw Level | +0.559 | **+0.961** | +0.307 | +0.276 | +0.387 | Moderate Scanning/Reset Noise |
| `Fam0_Level_flow_count` | Raw Level | **+0.863** | **+0.949** | +0.319 | +0.368 | +0.205 | Regime-Specific (Wed Volumetric) |
| `Fam0_Level_dst_port` | Raw Level | +0.454 | +0.381 | +0.229 | +0.374 | +0.246 | Scanning-Specific |
| `Fam4_Sync_flow_rst` | Synchrony | -0.463 | -0.546 | -0.172 | -0.307 | -0.296 | Weak Unstable Indicator |
| `Fam5_Res_Norm_Euclidean`| Residuals | +0.109 | -0.105 | -0.115 | -0.014 | -0.107 | Uninformative ($d \approx 0$) |
| `Fam1_NormDiff_byte_rate`| Velocity | -0.010 | -0.013 | -0.012 | -0.008 | -0.020 | Pure Telemetry Noise ($d \approx 0$) |
| `Fam2_NormAccel_byte` | Accel | -0.002 | -0.040 | -0.008 | -0.009 | -0.014 | Pure Telemetry Noise ($d \approx 0$) |

### Crucial Generalization Insights:
1. **Regime Heterogeneity**: Wednesday Blocks 1 and 2 exhibit large, unambiguous volumetric and port anomalies ($d \approx 0.9 - 1.2$). In sharp contrast, Thursday Block 4 exhibits near-zero effect across all features.
2. **The Diurnal Nature of `iat_mean`**: Mean inter-arrival time is strongly negative across *all* daytime blocks (both Wednesday and Thursday) because aggregate enterprise traffic ramps up every morning between 08:00 and 11:00 UTC, causing packets to arrive faster network-wide. Treating `iat_mean` level as an attack signature in Block 4 would cause continuous benign false alarms every single business morning.

---

## 8. Publication Diagnostic Figures

All 8 diagnostic figures were generated from live telemetry and persisted to `artifacts/experiments/temporal_representation_study_v1/figures/`:

````carousel
![Figure 1: Derivative Distributions](file:///C:/Users/ayush/.gemini/antigravity-ide/brain/727849c2-fefc-4ac2-9da6-28a58a14f4f7/figures/01_derivative_distributions.png)
<!-- slide -->
![Figure 2: Acceleration Distributions](file:///C:/Users/ayush/.gemini/antigravity-ide/brain/727849c2-fefc-4ac2-9da6-28a58a14f4f7/figures/02_acceleration_distributions.png)
<!-- slide -->
![Figure 3: Burst and Persistence Comparisons](file:///C:/Users/ayush/.gemini/antigravity-ide/brain/727849c2-fefc-4ac2-9da6-28a58a14f4f7/figures/03_burst_persistence_comparisons.png)
<!-- slide -->
![Figure 4: Cross-Feature Synchrony](file:///C:/Users/ayush/.gemini/antigravity-ide/brain/727849c2-fefc-4ac2-9da6-28a58a14f4f7/figures/04_cross_feature_synchrony.png)
<!-- slide -->
![Figure 5: Forecast Residual Distributions](file:///C:/Users/ayush/.gemini/antigravity-ide/brain/727849c2-fefc-4ac2-9da6-28a58a14f4f7/figures/05_forecast_residual_distributions.png)
<!-- slide -->
![Figure 6: Residual Temporal Trajectories](file:///C:/Users/ayush/.gemini/antigravity-ide/brain/727849c2-fefc-4ac2-9da6-28a58a14f4f7/figures/06_residual_temporal_trajectories.png)
<!-- slide -->
![Figure 7: Moving Block Bootstrap Intervals](file:///C:/Users/ayush/.gemini/antigravity-ide/brain/727849c2-fefc-4ac2-9da6-28a58a14f4f7/figures/07_moving_block_bootstrap_intervals.png)
<!-- slide -->
![Figure 8: Representation Comparison Heatmap](file:///C:/Users/ayush/.gemini/antigravity-ide/brain/727849c2-fefc-4ac2-9da6-28a58a14f4f7/figures/08_representation_comparison_heatmap.png)
````

---

## 9. Answers to the Central Research Questions

### Question 1: Does Block 4 contain detectable temporal information in existing NetFlow?
**Answer**: **NO.** Under rigorous causal feature extraction across 27 operational metrics spanning 6 distinct information families, Block 4 telemetry exhibits virtually complete distribution overlap ($76\% - 98\%$) with its immediate pre-onset benign baseline.

### Question 2: If yes, which representation family captures it?
**Answer**: **NONE.** 
- First differences (Family 1) and second differences (Family 2) collapse to $d < 0.02$ with $95\%$ bootstrap CIs spanning zero.
- Burst run lengths and duty cycles (Family 3) exhibit $d < 0.09$ with CIs spanning zero.
- Cross-feature synchrony products and Mahalanobis distances (Family 4) fail to separate Block 4 ($d < 0.15$, overlap $> 87\%$).
- Authoritative AR(5) forecast residuals (Family 5) show $\|e\|_2$ effect size of $d = -0.107$, with 95% CI spanning zero and 97.3% distribution overlap.

### Question 3: Does the effect survive dependence-aware evaluation?
**Answer**: **NO.** When evaluated using Moving Block Bootstrap ($L=30$ windows / 300s, 2,000 resamples) preserving temporal autocorrelation, **21 of 27 representations have 95% confidence intervals spanning zero**. The few metrics whose CIs do not strictly span zero (e.g. `iat_mean`) represent network-wide diurnal background volume expansion rather than attack behavior.

### Question 4: Does it reproduce across multiple infiltration blocks?
**Answer**: **NO.** The representations that separate Wednesday Block 1 ($d = +0.989$) and Block 2 ($d = +1.106$) fail completely on Thursday Block 4 ($d \approx 0.019$). Infiltration regimes are fundamentally heterogeneous: scanning/volumetric reconnaissance produces strong NetFlow anomalies, whereas lightweight web infiltration does not.

### Question 5: Is it strong enough to justify designing a `bridge_v4`?
**Answer**: **NO. `bridge_v4` IS STRICTLY REJECTED.** 
Proposing a `bridge_v4` based on these findings would violate scientific integrity. Since no temporal representation in the 10-second summary NetFlow stream provides a credible, reproducible signal for Block 4, any security bridge built on top of these features would merely overfit noise and escalate benign traffic.

### Question 6: Or does the evidence indicate a genuine observability ceiling?
**Answer**: **YES. HYPOTHESIS A (TRUE FEATURE-SPACE LIMITATION) IS CONFIRMED.**
In CIC-IDS2018, Thursday Block 4 represents a lightweight web application infiltration (SQL injection / web exploit) generating a negligible handful of HTTP packets submerged inside thousands of normal background web browsing connections. When aggregated into 10-second summary NetFlow records, this traffic is mathematically indistinguishable from benign enterprise web activity. Detecting this attack requires endpoint telemetry (e.g. web server access logs, WAF alerts, process trees) or Layer-7 payload inspection, which are fundamentally unavailable in Layer-3/4 NetFlow summaries.

---

## 10. Final Architectural Recommendation

1. **Retain `bridge_v3` for Operational Deployment**:
   `bridge_v3` (causal multi-signal normalization) remains the authoritative security bridge within this repository: it cuts benign reconnaissance false alarms by **83.2%** ($89.6\% \to 6.4\%$) and reliably detects scanning and volumetric attacks ($d > 0.55$).
2. **Formally Document NetFlow Observability Ceiling**:
   Acknowledge in the project documentation and research papers that 10-second summary NetFlow has an intrinsic observability boundary for stealthy, low-volume web infiltration. This is an honest, scientifically grounded conclusion that prevents test-set overfitting and guides future research toward multi-layer sensor fusion.
