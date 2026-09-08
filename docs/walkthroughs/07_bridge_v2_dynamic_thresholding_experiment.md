# A/B Experiment: Dynamic Rolling-Baseline vs Static Thresholding in BehavioralSecurityBridge

**SIH PS 26153**: AI-Based Network Attack Forecasting from Network Traffic Data  
**Repository**: `sih1`  
**Experiment ID**: `bridge_ab_experiment_v1`  
**Evaluation Date**: 2026-09-05  

---

## Executive Summary & Explicit Verdict

| Evaluation Scope | Metric | OLD_STATIC Bridge | NEW_ROLLING Bridge | Empirical Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Benign Telemetry** ($N=1339$) | False Recon Trigger Rate | **89.6%** | **12.7%** | **IMPROVED** (-76.9% false triggers) |
| **Immediate Pre-Onset Context** ($N=584$) | False Recon Trigger Rate | **94.3%** | **11.5%** | **IMPROVED** (-82.8% false triggers) |
| **Pooled Infiltration (All 4 Blocks, $N=1708$)** | Cohen's $d$ / Overlap | $d = 0.508$ / $73.3\%$ | **$d = 0.582$ / $70.5\%$** | **IMPROVED** (+14.5% effect size) |
| **Wednesday Infiltration (Blocks 1 & 2)** | Cohen's $d$ (Wed B1, Wed B2) | $+0.756$, $+0.868$ | **$+1.033$, $+1.175$** | **IMPROVED** (Large effect size $\ge 1.0$) |
| **Thursday Block 4 vs Pre-Onset Context** | Cohen's $d$ (Primary Benchmark) | $d = +0.035$ | $d = -0.008$ | **NO MEANINGFUL CHANGE** |
| **Thursday Block 4 vs Pre-Onset Context** | 95% CI on Mean Diff | $[-0.020, +0.029]$ | $[-0.041, +0.035]$ | **NO MEANINGFUL CHANGE** (Spans zero) |
| **Thursday Block 4 vs Pre-Onset Context** | Distribution Overlap | $91.9\%$ | $89.2\%$ | **NO MEANINGFUL CHANGE** |
| **Experiment D (Contradiction)** | Trust Drop & Risk Dampening | Confirmed ($63.2\%$) | Confirmed ($49.8\%$) | **PRESERVED** (No regression) |

### Explicit Verdict
**REGIME-DEPENDENT (IMPROVED for scanning/multi-target attacks; NO MEANINGFUL CHANGE for stealthy single-target web infiltration)**.
- **For Benign Normal Traffic**: The hypothesis is **strongly validated**. Replacing static thresholds with a causal rolling baseline ($W=30$ windows / 300s, $k=3.0$ MAD) eliminates over $85\%$ of false reconnaissance signatures caused by legitimate enterprise multi-port traffic (CDNs, DNS, microservices).
- **For Wednesday Infiltration (Blocks 1 & 2)**: The hypothesis is **strongly validated**. Cohen's $d$ increases from $+0.76 \to +1.03$ (Block 1) and $+0.87 \to +1.18$ (Block 2), with distribution overlap dropping from $62.3\% \to 51.8\%$ and $58.7\% \to 50.1\%$.
- **For Thursday Infiltration (Block 4 against immediate pre-onset context)**: The result is **NO MEANINGFUL CHANGE** ($d = +0.035 \to -0.008$, 95% bootstrap CI $[-0.041, +0.035]$ spans zero). 
- **Underlying Reason**: In CIC-IDS2018 Thursday Infiltration (Dropbox download / web exploitation), the attack traffic **does not scan destination ports** (attack median `dst_port_diversity = 20.0` vs benign morning background median `22.0`). Because the dynamic baseline suppresses port exploration when port diversity matches recent background, it suppresses it equally on benign traffic and Thursday attack traffic. Interpretation layer logic cannot manufacture separation from a port-diversity signal when the attack does not deviate on that dimension.

---

## Complete Side-by-Side Comparison Table

All metrics evaluated on identical test splits and seeds ($N=1339$ benign, $N=584$ pre-onset benign, $N=343$ Block 4, $N=1708$ across all 4 infiltration blocks). Temporal autocorrelation preserved via Moving Block Bootstrap ($B=30$ windows / 300s, 2000 resamples).

| Metric | OLD_STATIC Bridge | NEW_ROLLING Bridge | Change / Significance |
| :--- | :--- | :--- | :--- |
| **Recon Flag Rate (Benign All, N=1339)** | 89.6% | 12.7% | -76.9% (Drastic reduction in false alarms) |
| **Recon Flag Rate (Benign Pre, N=584)** | 94.3% | 11.5% | -82.8% (False reconnaissance suppressed) |
| **Recon Flag Rate (Attack B4, N=343)** | 96.5% | 13.1% | -83.4% (Attack does not exhibit elevated ports) |
| **Benign Mean $R(t)$** | 0.3172 | 0.2581 | -0.0591 (Lower baseline risk) |
| **Benign Median $R(t)$** | 0.2525 | 0.1836 | -0.0689 (Shifted towards Low risk band) |
| **Benign Std $R(t)$** | 0.1242 | 0.1586 | +0.0344 (Higher dispersion during adaptation) |
| **Benign False Escalations ($R \ge 0.50, \ge 3$w)** | 5 | 17 | +12 episodes (Due to trailing baseline lag during rapid shifts) |
| **Pre-onset Benign Mean $R(t)$** | 0.3496 | 0.2990 | -0.0506 |
| **Pre-onset Benign Median $R(t)$** | 0.3443 | 0.2525 | -0.0918 |
| **Attack B4 Mean $R(t)$** | 0.3541 | 0.2975 | -0.0566 (Drops proportionally to benign) |
| **Attack B4 Median $R(t)$** | 0.3902 | 0.2525 | -0.1377 |
| **Attack All 4 Blocks Mean $R(t)$** | 0.3868 | 0.3686 | -0.0182 |
| **Attack All 4 Blocks Median $R(t)$** | 0.3902 | 0.3443 | -0.0459 |
| **B4 vs Benign All: Observed Mean Diff** | +0.0369 | +0.0394 | +0.0025 |
| **B4 vs Benign All: Mean Diff 95% CI** | [+0.0118, +0.0579] | [+0.0041, +0.0663] | Strictly positive (excluding zero) |
| **B4 vs Benign All: Overlap Coefficient** | 0.8260 | 0.8272 | Identical (~82.7%) |
| **B4 vs Benign All: Cohen's $d$** | 0.2954 | 0.2447 | Small effect size |
| **B4 vs Pre-onset: Observed Mean Diff** | +0.0045 | -0.0014 | Near zero |
| **B4 vs Pre-onset: Mean Diff 95% CI** | [-0.0199, +0.0289] | [-0.0413, +0.0354] | **Spans zero** (No statistical separation) |
| **B4 vs Pre-onset: Overlap Coefficient** | 0.9188 | 0.8917 | -2.7% (Still high overlap ~89%) |
| **B4 vs Pre-onset: Cohen's $d$** | 0.0349 | -0.0083 | **Negligible / Unchanged** |
| **All Blocks vs Benign All: Cohen's $d$** | 0.5084 | 0.5820 | **+0.0736 (+14.5% improvement)** |
| **All Blocks vs Benign All: Overlap Coef** | 0.7332 | 0.7050 | **-0.0282 (Lower overlap)** |
| **Exp D: Trust Drop Confirmed** | True | True | Verified: drops to $0.35$ on contradiction |
| **Exp D: Risk Dampening % post-reversal** | 63.2% | 49.8% | Verified: risk dampens substantially |

---

## Per-Block Generalization Breakdown

Does the improvement hold across all 4 infiltration blocks individually?

| Block ID | Scenario Description | N | OLD Mean | NEW Mean | OLD $d$ | NEW $d$ | OLD Overlap | NEW Overlap | Assessment |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **block-1-wed** | Wednesday Afternoon (01:42 - 02:39) | 343 | 0.4150 | 0.4343 | **+0.756** | **+1.033** | 0.623 | **0.518** | **SUBSTANTIAL IMPROVEMENT** |
| **block-2-wed** | Wednesday Late Afternoon (10:50 - 12:04) | 445 | 0.4315 | 0.4652 | **+0.868** | **+1.175** | 0.587 | **0.501** | **SUBSTANTIAL IMPROVEMENT** |
| **block-3-thu** | Thursday Morning (02:00 - 03:36) | 577 | 0.3549 | 0.2972 | +0.293 | +0.236 | 0.843 | 0.877 | Neutral / No scan activity |
| **block-4-thu** | Thursday Late Morning (09:57 - 10:54) | 343 | 0.3541 | 0.2975 | +0.295 | +0.245 | 0.826 | 0.827 | Neutral / No scan activity |

### Key Generalization Insight
1. **Blocks 1 & 2 (Wednesday)**: The attacks involve network scanning and service enumeration that genuinely exceed normal diurnal baseline. Eliminating benign false reconnaissance flags exposes a **large effect size ($d > 1.0$)** and drives distribution overlap down to $\sim 50\%$.
2. **Blocks 3 & 4 (Thursday)**: The attack is a stealthy web client infiltration (targeted HTTP download and local execution). Destination port diversity during the attack is identical to background normal traffic. Consequently, modifying port diversity thresholding has **zero leverage** on separating Thursday infiltration from Thursday background traffic.

---

## Parameter Selection Provenance (Strictly Pre-Test Split)

To satisfy the non-negotiable methodology requirements, parameters for `RollingBaselineSecurityBridge` were selected **exclusively from data prior to the Thursday 08:19:40 test split boundary**:
- **Calibration Split**: Thursday 01-03-2018 from `04:00:00` to `08:00:00` UTC ($N=625$ consecutive 10s windows).
- **Background Port Statistics**:
  - Median: $18.0$
  - Mean: $25.55$
  - Dispersion (MAD): $3.0$
- **Selected Parameters**:
  - `rolling_window_length` = $30$ windows ($300$ seconds / $5$ minutes)
  - `k_mad` = $3.0$ (standard $3\times$ MAD anomaly threshold)
  - `min_mad` = $2.0$ (dispersion floor preventing division-by-zero or extreme sensitivity in steady-state regimes)
- **Pre-Test Calibration Result**: Under static thresholding ($\ge 15$), $81.28\%$ of pre-test windows triggered false reconnaissance. Under $W=30, k=3.0$, false triggers dropped to **$4.19\%$**.

---

## Visual Comparison

![BehavioralSecurityBridge A/B Experiment](file:///C:/Users/ayush/.gemini/antigravity-ide/brain/727849c2-fefc-4ac2-9da6-28a58a14f4f7/bridge_ab_comparison.png)

- **Top-Left (Density)**: Shows the distribution of benign vs attack $R(t)$ under the new rolling bridge.
- **Top-Right (Cohen's d)**: Shows large improvements in effect size for Wednesday Blocks 1 and 2 ($d > 1.0$), while Thursday Blocks 3 and 4 remain around $d \approx 0.24$.
- **Bottom-Left (Overlap)**: Shows overlap reduction from $62\% \to 51\%$ in Block 1 and $59\% \to 50\%$ in Block 2.
- **Bottom-Right (Contradiction Dynamics)**: Demonstrates that Experiment D trust-drop and risk dampening behave consistently across both bridges.

---

## Regression & Test Suite Verification

- **Full Repository Test Suite**: `Ran 220 tests in 9.121s — OK (100% passing)`.
- **Targeted Validation Suite**:
  - `tests/test_future_security_risk_validation.py`: Passed (9/9)
  - `tests/test_future_security_risk.py`: Passed (13/13)
  - `tests/test_statistical_hardening.py`: Passed (11/11)
  - `tests/test_final_evidence.py`: Passed (10/10)
  - `tests/test_bridge_v2.py`: Passed (7/7)
    - Zero future leakage under sequence truncation: Verified
    - Score bounds $[0.0, 1.0]$: Verified
    - Determinism upon reset: Verified
    - Dynamic adaptation to stationary background: Verified
    - Experiment D contradiction preservation: Verified
- **Architectural Scope**: Zero modifications made to `core/contracts.py`, `eval/dataset.py`, `runtime/train_authoritative_model.py`, `eval/rollout.py`, AR(5) model weights, or the `SecurityRiskEngine` dampening formula. Original `security/bridge.py` remains 100% intact.

---

## Explicit Remaining Limitations

1. **Feature Telemetry Blindness**: In CIC-IDS2018, Thursday infiltration does not scan ports; it leverages single-port web communication (ports 80/443). As long as the primary heuristic driver for Initial Access/Reconnaissance is port diversity, no thresholding scheme (static or dynamic) can separate attacks that lack port anomalies.
2. **Dynamic Baseline Adaptation Lag**: When network activity undergoes legitimate rapid step changes (e.g. business hours opening between 08:30 and 09:00), the rolling median takes several windows to adjust. This caused brief clusters of false escalations ($R \ge 0.50$ for $\ge 3$ windows) to increase from 5 to 17 during morning ramp-up.
3. **Multi-Signal Requirement for Stealth Attacks**: Separating stealthy infiltration requires correlating flow inter-arrival regularity (`iat_std`), asymmetric byte transfers (`byte_rate`), or L7 URI/payload telemetry rather than relying on destination port diversity alone.
