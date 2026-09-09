# Phase 4 Experiment B — Actionable Lead Time & Human Review Latency Summary

- **Experiment Name**: `phase4_lead_time_v1`
- **Git Commit SHA**: `7ec690bbc997e47ea501f5b33b04ea2490e9d584` (Dirty: `True`)
- **Experiment Seed**: `42`
- **Fidelity Disclosure**: `PARAMETERIZED_STATE_TRANSFORMATION_NOT_HARDWARE_INLINE`
- **Telemetry Source**: `SYNTHETIC_CONTROLLED_SCENARIO`
- **Epistemic Status**: `OBSERVATIONAL_TRAJECTORY_VERIFICATION_NON_PEARLIAN`
- **Predefined Lead Time Criterion**: $\ge 10.0\text{s}$ at $\tau_{\text{exec}} = 0\text{s}$
- **Empirical Lead Time at $\tau=0\text{s}$**: **5.6s**
- **Monotonicity Across Latencies**: **Satisfied**
- **Scientific Verdict**: **WEAKENED**

### Latency Sweep Breakdown
| Latency Regime ($\tau$) | B0 (Conventional) Lead | B1 (Logistic Reg) Lead | B2 (Predictive) Lead | B2 95% Bootstrap CI | B2 vs B0 $p$-value | B2 vs B0 Cliff's $d$ |
|---|---|---|---|---|---|---|
| $\tau = 0\text{s}$ | 1.1s | 48.9s | **5.6s** | [1.1, 10.0] | 0.0625 | 0.346 |
| $\tau = 5\text{s}$ | 0.6s | 43.9s | **3.3s** | [0.6, 6.7] | 0.0625 | 0.346 |
| $\tau = 10\text{s}$ | 0.0s | 38.9s | **1.1s** | [0.0, 3.3] | 1.0000 | 0.111 |
| $\tau = 20\text{s}$ | 0.0s | 28.9s | **0.0s** | [0.0, 0.0] | 1.0000 | 0.000 |

### False Alert Rates on Benign Scenarios
- **B0 (Conventional Threshold)**: 0.0%
- **B1 (Logistic Regression)**: 100.0%
- **B2 (Predictive Trajectory)**: 66.7%
