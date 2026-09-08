# Walkthrough: Day 5 — Multi-Step Rollout & Uncertainty Quantification (delta_rollout_uncertainty_v1)

## Summary of Accomplishments

1. **Reproduction of AR(5) Baseline (Part A & B)**:
   - Evaluated AR(5) on 6,703 contiguous multi-step samples extracted from real Wednesday and Thursday CIC-IDS2018 state sequences.
   - Exact 1-step reproduction confirmed: Norm MAE = 187.01, Median Norm MAE = 0.4041, Directional Accuracy = 68.09% (Non-zero DA = 69.56%).

2. **Recursive Open-Loop Rollout ($h=1, 2, 3$, Part C)**:
   - Measured error compounding when predicted deltas are recursively fed into the model context without access to future ground truth.
   - Directional accuracy drops from $68.09\%$ at $h=1$ ($10\text{s}$) to $50.95\%$ at $h=2$ ($20\text{s}$) and $50.21\%$ at $h=3$ ($30\text{s}$), demonstrating that uncorrected open-loop rollouts degrade toward a martingale / random walk beyond 1–2 steps.

3. **Receding-Horizon Error Stabilization (Part D)**:
   - Evaluated step-by-step rolling forecasts where each newly observed real state updates the historical context.
   - Maintained Directional Accuracy at $\approx 68.10\%$ and Median Normalized MAE at $\approx 0.4038$ across all steps ($h=1, 2, 3$), confirming that receding-horizon updating resets error accumulation by conditioning on observed telemetry at each step.

4. **Training-Only Empirical Residual Bootstrap (Part E & G)**:
   - Generated $B=100$ bootstrap recursive rollouts using joint residual vectors drawn strictly from the training residual pool ($E_{\text{train}} \in \mathbb{R}^{N_{\text{train}} \times 15}$) to preserve cross-feature correlation.
   - Evaluated empirical prediction intervals on held-out test data:
     - **80% Nominal:** $h=1: 81.92\% (+1.92\%)$, $h=2: 83.37\% (+3.37\%)$, $h=3: 84.07\% (+4.07\%)$
     - **90% Nominal:** $h=1: 89.71\% (-0.29\%)$, $h=2: 90.88\% (+0.88\%)$, $h=3: 91.18\% (+1.18\%)$
     - **95% Nominal:** $h=1: 93.85\% (-1.15\%)$, $h=2: 94.68\% (-0.32\%)$, $h=3: 94.90\% (-0.10\%)$

5. **Multi-Future Trajectories ($K=3$, Part F)**:
   - Constructed $K=3$ candidate trajectories ($T_0$ deterministic/median 0.50 weight, $T_1$ 75th percentile upper variation 0.25 weight, $T_2$ 25th percentile lower variation 0.25 weight) satisfying all `core/contracts.py` invariants.

6. **Trust Degradation & Controlled Reconsideration (Part H & I)**:
   - Formulated composite trust score $T(h) \in [0, 1]$ based on interval width, residual variance, and historical error.
   - Trust scores decay monotonically with rollout horizon ($h=1: 0.20 \to h=2: 0.08 \to h=3: 0.05$).
   - Successfully executed the controlled Reconsideration test: observing deviating telemetry triggers context refresh, updates forecasts, and re-ranks candidate trajectories.

7. **Held-Out Infiltration Block Validation (Part J)**:
   - Evaluated across all 4 observed infiltration blocks, demonstrating consistent 1-step DA (67%–70%) and receding-horizon stabilization.

8. **Test Suite & Invariants (Part M)**:
   - 51 unit tests pass across `tests/` (`python -m unittest` and `python -m pytest`).

---

## Results Summary Table

### Multi-Step Horizon Performance (Open-Loop vs Receding-Horizon)

| Horizon | Open-Loop Norm MAE | Open-Loop Median Norm MAE | Open-Loop DA | Open-Loop DA (NZ) | Receding Norm MAE | Receding Median Norm MAE | Receding DA | Receding DA (NZ) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **$h=1$ ($10\text{s}$)** | 187.0073 | 0.4041 | **68.09%** | **69.56%** | 187.0073 | 0.4041 | **68.09%** | **69.56%** |
| **$h=2$ ($20\text{s}$)** | 187.1210 | 0.4711 | 50.95% | 52.05% | 187.0069 | **0.4039** | **68.09%** | **69.57%** |
| **$h=3$ ($30\text{s}$)** | 186.3133 | 0.4691 | 50.21% | 51.29% | 187.0064 | **0.4037** | **68.11%** | **69.59%** |

### Empirical Prediction Interval Coverage (Test Set)

| Nominal Level | Horizon $h=1$ | Horizon $h=2$ | Horizon $h=3$ | Calibration Quality |
| :---: | :---: | :---: | :---: | :---: |
| **80%** | 81.92% ($+1.92\%$) | 83.37% ($+3.37\%$) | 84.07% ($+4.07\%$) | High |
| **90%** | 89.71% ($-0.29\%$) | 90.88% ($+0.88\%$) | 91.18% ($+1.18\%$) | Excellent |
| **95%** | 93.85% ($-1.15\%$) | 94.68% ($-0.32\%$) | 94.90% ($-0.10\%$) | Excellent |

---

## Artifacts Generated
- Manifest: [`manifest.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_rollout_uncertainty_v1/manifest.json)
- Summary: [`results_summary.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_rollout_uncertainty_v1/results_summary.json)
- Horizon Metrics: [`horizon_metrics.csv`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_rollout_uncertainty_v1/horizon_metrics.csv)
- Receding vs Open Loop: [`receding_vs_open_loop.csv`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_rollout_uncertainty_v1/receding_vs_open_loop.csv)
- Coverage: [`coverage.csv`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_rollout_uncertainty_v1/coverage.csv)
- Trust Metrics: [`trust_metrics.csv`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_rollout_uncertainty_v1/trust_metrics.csv)
- Trajectory Samples: [`trajectory_samples.jsonl`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_rollout_uncertainty_v1/trajectory_samples.jsonl)
- Per-Block Folds: [`per_block_results.csv`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_rollout_uncertainty_v1/per_block_results.csv)
