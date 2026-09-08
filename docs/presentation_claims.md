# SIH 26153 — One-Sentence Presentation Claims & Epistemic Boundaries

---

## Metric 1: Dataset Scope (8,640 Network States)
- **Exact Allowed Claim:** "The predictive dynamics pipeline was evaluated on 172,800 seconds (8,640 consecutive 10-second NetworkState observations) of windowed transport telemetry from CSE-CIC-IDS2018."
- **Exact Caveat:** CSE-CIC-IDS2018 is a benchmark dataset; 6 host topology features (`fan_out`, internal ratios) are unavailable in NetFlow CSV records and strictly masked.
- **Prohibited Stronger Wording:** "Evaluated on live wire-speed 100Gbps enterprise campus network traffic."

---

## Metric 2: AR(5) Directional Predictive Accuracy (68.10%)
- **Exact Allowed Claim:** "Linear autoregressive dynamics AR(5) achieves 68.10% directional accuracy on the chronological test split (95% Moving Block Bootstrap CI: [67.32%, 68.87%]), drastically outperforming ZeroChange (2.11%) and Persistence (32.89%)."
- **Exact Caveat:** Evaluated on 10-second short-horizon delta state transitions; open-loop recursive projections without new telemetry degrade to ~50% at 30 seconds.
- **Prohibited Stronger Wording:** "AR(5) predicts all cyber attacks with 68% accuracy."

---

## Metric 3: AR(5) vs AR(3) Model Improvement (+0.82 pp on Test Split)
- **Exact Allowed Claim:** "AR(5) exceeds AR(3) by +0.82 percentage points on aligned test transitions (95% CI: [+0.23%, +1.38%], McNemar p = 2.74e-4) while losing zero valid forecasts across active attack periods."
- **Exact Caveat:** AR(5) requires 6 consecutive states (5 historical deltas) for cold start; an automated fallback to AR(3) is engaged when fewer deltas are present.
- **Prohibited Stronger Wording:** "AR(5) is universally superior across all network contexts regardless of telemetry availability."

---

## Metric 4: Empirical Uncertainty Calibration (89.71% Coverage)
- **Exact Allowed Claim:** "Training-only empirical residual bootstrap produces calibrated prediction intervals, achieving 89.71% empirical coverage at the nominal 90% target (coverage error of only -0.29%)."
- **Exact Caveat:** Intervals quantify marginal per-feature state variance, not a calibrated full joint posterior probability distribution.
- **Prohibited Stronger Wording:** "The system computes exact joint Bayesian attack probabilities."

---

## Metric 5: Simulated Response-Window Gain (+10.0s Useful Gain)
- **Exact Allowed Claim:** "Predictive trajectory forecasting provided a 10.0-second simulated useful response-window gain across 3/3 controlled attack progressions, allowing a modeled 20-second reversible preparation action to complete before sustained event onset."
- **Exact Caveat:** Action execution duration is simulated (fixed 20s execution model); does NOT measure live human SOC analyst cognitive triage latency.
- **Prohibited Stronger Wording:** "The system reduces real-world enterprise SOC incident response time by 10 seconds."

---

## Metric 6: False Alarm Suppression (0 in 32 Tested Windows)
- **Exact Allowed Claim:** "The predictive trajectory detector produced 0 false positive alerts across 32 tested controlled benign burst and ambiguous noise evaluation windows (exact Clopper-Pearson 95% upper bound: 10.89%)."
- **Exact Caveat:** Observed zero false alarms in 32 controlled test windows does NOT guarantee zero false alarms in production enterprise networks.
- **Prohibited Stronger Wording:** "The system achieves a guaranteed 0% false positive rate in production."

---

## Metric 7: Decision Layer Safety & Human Gating (13/13 Invariants Passed)
- **Exact Allowed Claim:** "100% of generated response recommendations enforce mandatory human analyst approval gates and reversible mitigation strategies, with zero autonomous destructive execution."
- **Exact Caveat:** The system functions as an analyst decision-support tool, not an autonomous agent.
- **Prohibited Stronger Wording:** "Autonomous self-defending AI that eliminates human SOC analysts."

---

## Metric 8: Repository Test Suite Integrity (158/158 Passing Tests)
- **Exact Allowed Claim:** "The complete repository test suite contains 158 unit, integration, and statistical validation tests passing cleanly with 100% pass rate."

- **Exact Caveat:** Unit tests verify internal architectural invariants and mathematical correctness across controlled fixtures and datasets.
- **Prohibited Stronger Wording:** "Passing tests prove immunity to all real-world evasion techniques."
