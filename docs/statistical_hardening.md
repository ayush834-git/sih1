# SIH 26153 — Statistical Hardening & Effect-Size Dossier

---

## 1. Executive Summary & Authoritative Numbers

| Metric Domain | Aligned $N$ | Point Estimate | Uncertainty Interval (95% Bounds) | Statistical Method | Provenance / Caveat |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **AR(5) Test Directional Accuracy** | 1,682 transitions (25,230 evaluations) | **`68.10%`** | **`[67.32%, 68.87%]`** (SE = 0.0040) | Moving Block Bootstrap ($B=12$, $n_{\text{boot}}=2000$) | Evaluated on 10s windowed transport telemetry. |
| **AR(5) vs AR(3) Directional Accuracy Gain** | 1,682 aligned test transitions | **`+0.82%`** (test) / **`+1.84%`** (global) | **`[+0.23%, +1.38%]`** (test) / **`[+1.28%, +2.41%]`** (global) | Paired Moving Block Bootstrap ($B=12$, $n_{\text{boot}}=2000$) | McNemar $\chi^2 = 13.24$, $p = 2.74 \times 10^{-4}$; Cohen's $d_z = 0.07$. |
| **Infiltration Block Variability** | 4 observed blocks (1,708 states) | Mean **`+1.69%`** (Median: `+1.85%`) | Range: **`[+0.91%, +2.16%]`** (Spread: `1.24%`) | Leave-One-Block-Out (LOBO) min-max spread | Descriptive variability across 4 episodic attack periods; not large-N power. |
| **Simulated Response-Window Gain** | 3 controlled progressions | **`+10.0s`** | **`10.0s across all 3 scenarios`** | Deterministic Progression Replay | 10.0s raw lead time; modeled 20s reversible preparation action. |
| **Scenario False Positive Rate** | 2 scenarios (32 evaluation windows) | **`0.00%`** | **`[0.00%, 10.89%]`** (Clopper-Pearson 95% Bound) | Exact Binomial Upper Bound | Observed 0 false positives across 32 tested replay windows; does NOT guarantee 0% in production. |

---

## 2. Temporal Dependence & Autocorrelation Justification

In discrete 10-second network telemetry streams, adjacent windows exhibit serial autocorrelation. Standard random IID bootstrap resampling breaks this temporal ordering, yielding artificially narrow, non-generalizable confidence intervals.

To establish defensible, rigorous uncertainty bounds:
1. **Resampling Architecture:** **Moving Block Bootstrap (MBB)**.
2. **Block Length Selection ($B=12$):** A block size of 12 consecutive 10-second windows represents **120 seconds of continuous telemetry**. This preserves both the immediate transition inertia (10–30s) and extended multi-window burstiness.
3. **Replication Budget:** $n_{\text{boot}} = 2,000$ resamples with fixed pseudo-random seed ($42$).

---

## 3. Paired Model Comparison: AR(5) vs AR(3)

Across 1,682 aligned test transitions (evaluating 25,230 feature transitions):
- **AR(5) Point Accuracy:** $68.10\%$
- **AR(3) Point Accuracy:** $67.28\%$
- **Paired Mean Difference:** $+0.82\%$ ($+1.84\%$ on full dataset)
- **95% Block Bootstrap Confidence Interval:** $[+0.23\%, +1.38\%]$
- **Paired Cohen's $d_z$:** $0.0695$
- **McNemar's Discordant Test:**
  - $b = 1,690$ transitions (AR(5) correct, AR(3) wrong)
  - $c = 1,484$ transitions (AR(3) correct, AR(5) wrong)
  - McNemar $\chi^2 = 13.24$, $p = 2.74 \times 10^{-4}$ (Odds Ratio: $1.1388$)

---

## 4. Infiltration-Block-Level Generalization (Small-N Characterization)

Evaluation across the four observed CSE-CIC-IDS2018 infiltration blocks under Leave-One-Block-Out:

| Block ID | Block Name | Day | States ($N$) | AR(3) DA | AR(5) DA | Gain ($\Delta$) |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| `block-1-wed` | Wednesday Block 1 (01:42 - 02:39) | Wed | 343 | 65.75% | **67.91%** | **+2.16%** |
| `block-2-wed` | Wednesday Block 2 (10:50 - 12:04) | Wed | 445 | 67.36% | **68.94%** | **+1.59%** |
| `block-3-thu` | Thursday Block 3 (02:00 - 03:36) | Thu | 577 | 68.30% | **70.40%** | **+2.10%** |
| `block-4-thu` | Thursday Block 4 (09:57 - 10:54) | Thu | 343 | 66.03% | **66.94%** | **+0.91%** |

- **Descriptive Statistics:**
  - Mean Gain: **`+1.69%`**
  - Median Gain: **`+1.85%`**
  - Min Gain: **`+0.91%`**
  - Max Gain: **`+2.16%`**
  - Spread: **`1.24%`**
- **Methodological Boundary:** $N=4$ blocks represents a descriptive variability characterization across observed attack intervals, NOT an asymptotic proof of universal generalization across arbitrary network architectures.

---

## 5. Response Window & False Positive Bounds

### Response Window ($N=3$ Controlled Progressions)
- **Reconnaissance Progression:** Onset at $60\text{s}$, Current-state alert at $50\text{s}$, Predictive alert at $40\text{s} \to \text{Lead Time} = 10.0\text{s}$, $\text{Useful Gain} = 10.0\text{s}$.
- **DoS Progression:** Onset at $60\text{s}$, Current-state alert at $50\text{s}$, Predictive alert at $40\text{s} \to \text{Lead Time} = 10.0\text{s}$, $\text{Useful Gain} = 10.0\text{s}$.
- **Exfiltration Progression:** Onset at $60\text{s}$, Current-state alert at $50\text{s}$, Predictive alert at $40\text{s} \to \text{Lead Time} = 10.0\text{s}$, $\text{Useful Gain} = 10.0\text{s}$.
- **Statistical Summary:** $\text{Mean} = 10.0\text{s}, \text{Median} = 10.0\text{s}, \text{Min} = 10.0\text{s}, \text{Max} = 10.0\text{s}, \text{Std} = 0.0\text{s}$.
- **Epistemic Note:** All 3 tested progression replays produced a 10s useful preparation gain under a modeled 20s action execution duration. This is reported as a deterministic benchmark property.

### False Positive Exact Bounds ($N=32$ Windows)
- **Tested Benign/Noise Windows:** 32 windows ($320\text{s}$ of continuous unattacked traffic across `transient_burst_noise` and `ambiguous_mixed_traffic`).
- **Observed False Positives:** $0$.
- **Empirical FPR:** $0.00\%$.
- **Exact Clopper-Pearson 95% Binomial Upper Bound:** **`10.89%`** ($1 - 0.025^{1/32}$).
- **Rule of Three Upper Bound:** **`9.38%`** ($3/32$).
- **Epistemic Distinction:** Observed zero false alarms in 32 controlled test windows; this does NOT imply a guaranteed zero false alarm rate in arbitrary uncurated enterprise environments.
