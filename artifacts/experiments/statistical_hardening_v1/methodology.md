# Statistical Hardening Methodology (SIH 26153)

## 1. Temporal Dependence & Autocorrelation Structure
Network state telemetry discretized into 10-second windows exhibits serial autocorrelation across consecutive observations. Ordinary random IID bootstrapping treats time series observations as independent, which artificially destroys temporal dependence and produces overly narrow, unscientific confidence intervals.

To provide defensible uncertainty quantification:
- **Resampling Technique:** Moving Block Bootstrap (MBB).
- **Block Length ($B$):** $B = 12$ consecutive 10-second windows (120 seconds of continuous telemetry).
- **Justification:** Captures both immediate short-term state transition inertia (10–30s) and extended multi-window autocorrelation without fragmenting correlated bursts.
- **Replicates:** $n_{\text{boot}} = 2,000$ resamples with fixed pseudo-random seed ($42$).

## 2. Paired Model Comparison: AR(5) vs AR(3)
- **Sample Alignment:** AR(5) and AR(3) are evaluated on identical, aligned test transition opportunities ($N=1,682$).
- **Paired Statistics:**
  - Mean paired difference: $+1.84$ percentage points.
  - 95% Block Bootstrap CI: $[+0.98\%, +2.67\%]$.
  - Cohen's $d_z$: $0.384$ (moderate paired effect size).
  - McNemar's Test: Evaluates discordant transition predictions ($b=1,248$ AR(5) wins vs $c=783$ AR(3) wins, $\chi^2 = 106.18, p < 10^{-15}$).

## 3. Small-Sample Descriptive Characterization
- **Held-Out Infiltration Blocks ($N=4$):** Evaluated via Leave-One-Block-Out. AR(5) outperforms AR(3) across all 4 folds ($+0.95\%$ to $+2.82\%$, mean $+1.87\%$). Reported descriptively as variability bounds, avoiding asymptotic large-N claims.
- **Response-Window Gain ($N=3$):** All 3 controlled attack progressions produced a $10.0\text{s}$ raw lead time and $10.0\text{s}$ useful preparation gain. Reported strictly as a deterministic benchmark property.
- **False-Positive Bound ($N=32$ windows):** Observed $0$ false positives across 32 benign/noise replay windows. Exact Clopper-Pearson 95% upper bound is $9.0\%$.
