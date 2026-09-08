# Walkthrough: Future Security Risk $R(t+h)$ Empirical Validation (SIH PS 26153)

A rigorous empirical validation harness has been constructed and executed for the existing **Future Security Risk trajectory $R(t+h)$** without altering the underlying AR(5) model or tuning the security risk engine.

---

## 1. Canonical Repository Mapping

| Pipeline Component | Canonical Implementation | Location | Role in Validation |
| :--- | :--- | :--- | :--- |
| **NetworkState** | `NetworkState` dataclass | [`core/contracts.py`](file:///c:/Users/ayush/sih1/core/contracts.py) | Schema representation of 10s evaluation windows |
| **State Loader** | `load_states_from_jsonl` | [`eval/dataset.py`](file:///c:/Users/ayush/sih1/eval/dataset.py) | Loads chronological JSONL state sequences |
| **Authoritative Model** | `load_ar_model` | [`runtime/train_authoritative_model.py`](file:///c:/Users/ayush/sih1/runtime/train_authoritative_model.py) | Loads frozen AR(5) coefficients & robust scales from `artifacts/models/ar5_authoritative` |
| **Rollout Engine** | `MultiStepRolloutEngine` | [`eval/rollout.py`](file:///c:/Users/ayush/sih1/eval/rollout.py) | Generates open-loop recursive forecasts $h \in \{1, 2, 3\}$ from rolling 5-step delta history |
| **Security Bridge** | `BehavioralSecurityBridge` | [`security/bridge.py`](file:///c:/Users/ayush/sih1/security/bridge.py) | Extracts behavioural signatures & infers MITRE-aligned stage hypotheses |
| **Risk Engine** | `SecurityRiskEngine` | [`security/risk_engine.py`](file:///c:/Users/ayush/sih1/security/risk_engine.py) | Computes bounded risk score $R(t+h) \in [0, 1]$ and trajectory |
| **Contradiction Fixture**| `get_demo_scenario_states` | [`scenarios/demo/scenarios.py`](file:///c:/Users/ayush/sih1/scenarios/demo/scenarios.py) | Canonical 16-step scenario `demo_recon_15s` with probe reversal |

---

## 2. Experimental Execution & Raw Empirical Results

### Experiment A: Benign / Non-Escalating Windows
Evaluated on the chronological test split of Thursday 01-03-2018 (08:19:40 to 12:59:50):
- **Benign Windows Evaluated**: $N = 1339$ total non-empty benign test windows (584 pre-onset consecutive windows + 755 post-block windows).
- **Mean Risk**: $0.3172$
- **Median Risk**: $0.2525$
- **Standard Deviation**: $0.1242$
- **Range**: Min $= 0.1463$, Max $= 0.6828$
- **Percentiles**: $p_{10} = 0.1836$, $p_{25} = 0.2525$, $p_{50} = 0.2525$, $p_{75} = 0.3902$, $p_{95} = 0.6828$
- **Proportion Above Descriptive Bands**:
  - $R \ge 0.25$: **$82.15\%$**
  - $R \ge 0.50$: **$7.24\%$**
  - $R \ge 0.75$: **$0.00\%$**
- **Linear Drift Slope**: $+3.05 \times 10^{-5}$ per window (essentially zero drift).
- **Empirical False Escalations**: **5 episodes** where $R \ge 0.50$ for $\ge 3$ consecutive windows without attack traffic.

### Experiment B: Attack / Infiltration Windows
Evaluated on chronological attack-onset and active infiltration portions:
- **Block 4 Active Windows** (Thursday 09:57 to 10:54): $N = 343$
- **Pre-Onset Context** (72 windows prior to onset, 09:45 to 09:56:50):
  - Mean $= 0.4058$, Median $= 0.3902$, Std $= 0.1366$
- **Onset Window Transition** ($t = \text{09:57:00}$):
  - Level $R(\text{onset}) = 0.3443$, first difference $\Delta R = -0.3385$ (dropped from pre-onset burst).
- **Active Infiltration Block 4 Statistics**:
  - Mean $= 0.3547$, Median $= 0.3902$, Std $= 0.1263$
  - Range: Min $= 0.1463$, Max $= 0.8291$
  - Percentiles: $p_{25} = 0.2525$, $p_{50} = 0.3902$, $p_{75} = 0.3902$, $p_{95} = 0.6828$
  - Linear Trend Slope post-onset: $-1.80 \times 10^{-5}$ per window (flat/noisy oscillation, no monotonic escalation).
- **All 4 Held-Out Infiltration Blocks ($N = 1708$ states)**:
  - Block 1 (Wed 01:42 - 02:39, $N=343$): Mean $= 0.4150$, Median $= 0.3902$, Max $= 0.8291$
  - Block 2 (Wed 10:50 - 12:04, $N=445$): Mean $= 0.4315$, Median $= 0.3902$, Max $= 0.8291$
  - Block 3 (Thu 02:00 - 03:36, $N=577$): Mean $= 0.3549$, Median $= 0.3902$, Max $= 0.8291$
  - Block 4 (Thu 09:57 - 10:54, $N=343$): Mean $= 0.3541$, Median $= 0.3902$, Max $= 0.8291$

### Experiment C: Benign vs Attack Statistical Comparison
- **Observed Difference in Medians**: $+0.1377$ (Attack median $0.3902$ vs Benign median $0.2525$)
- **Moving Block Bootstrap (Block Size = 30 windows / 300s, 2000 resamples)**:
  - 95% CI on Difference in Medians: **$[+0.0000, +0.1377]$**
  - 95% CI on Difference in Means: **$[+0.0120, +0.0580]$** (Observed Mean Diff: $+0.0375$)
- **Distribution Overlap Coefficient**: **$82.31\%$ overlap** ($0.8231$)
- **Cohen's d Effect Size**: **$0.3009$** (small to modest effect size)
- **Comparison Against Pre-Onset Benign Context Specifically**:
  - Observed Mean Diff: $+0.0051$ (95% CI: $[-0.0199, +0.0290]$ — includes zero)
  - Overlap Coefficient: **$91.59\%$**
  - Cohen's d: $0.0402$ (negligible)
- **Methodological Warning**: Naive i.i.d. Mann-Whitney U test yields $p = 3.29 \times 10^{-9}$, creating a severe false sense of separation by ignoring serial autocorrelation.

### Experiment D: Contradiction / Termination Behaviour
Evaluated on canonical `demo_recon_15s` (16 steps):
- **Phase 1 Baseline** (w00-w04): $R_0 = 0.1836$, Trust $= 0.85$, Stage $=$ `Unknown`, Priority $=$ `LOW`
- **Phase 2 Subtle** (w05): $R_0 = 0.1836$
- **Phase 3 Escalation** (w06-w08): $R_0$ peaks at **$0.1836$**, Stage $=$ `Reconnaissance`, Priority $=$ `MEDIUM`
- **Phase 4 Contradiction / Reversal** (w09-w11):
  - Telemetry contradicts forecast (ports drop $-15.0$)
  - Model Trust drops: **$0.85 \to 0.35$** (HIGH $\to$ LOW)
  - Risk score dampens: **$0.1836 \to 0.0676$** (**$-0.1160$**, a **$63.2\%$ reduction**)
  - Counter-evidence generated and suppressing factors activated
  - Priority de-escalates: `MEDIUM` $\to$ `LOW`
- **Phase 5 Recovery** (w12-w15): Baseline maintained at $R_0 = 0.0676$, Priority $=$ `LOW`

### Experiment E: Lookahead Horizon Dynamics ($h \in \{0, 1, 2, 3\}$)

| Horizon | Label | Seconds | Uncertainty | Certainty Retention $(1 - \text{unc})$ | Nominal Trust | Benign Mean Risk | Attack Mean Risk |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **$h=0$** | `NOW` | $0\text{s}$ | $0.10$ | $0.90$ | $0.85$ | $0.3172$ | $0.3547$ |
| **$h=1$** | `+10s` | $10\text{s}$ | $0.20$ | $0.80$ | $0.85$ | $0.2495$ | $0.2753$ |
| **$h=2$** | `+20s` | $20\text{s}$ | $0.35$ | $0.65$ | $0.75$ | $0.2010$ | $0.2139$ |
| **$h=3$** | `+30s` | $30\text{s}$ | $0.50$ | $0.50$ | $0.65$ | $0.1347$ | $0.1471$ |

**Conclusion on Horizons**: Risk scores monotonically attenuate with lookahead horizon ($NOW \to +30s$) due to open-loop trust degradation and certainty retention decay $(1 - \text{unc})$. The system refuses to project high-confidence speculative panic into distant horizons.

---

## 3. Generated Figures

The 6 high-resolution publication-quality plots were generated in [`artifacts/experiments/future_security_risk_validation_v1/figures`](file:///c:/Users/ayush/sih1/artifacts/experiments/future_security_risk_validation_v1/figures):

1. **Benign Risk Trajectory**:
   [`plot1_benign_risk_trajectory.png`](file:///c:/Users/ayush/sih1/artifacts/experiments/future_security_risk_validation_v1/figures/plot1_benign_risk_trajectory.png)
2. **Attack-Onset Trajectory**:
   [`plot2_attack_onset_trajectory.png`](file:///c:/Users/ayush/sih1/artifacts/experiments/future_security_risk_validation_v1/figures/plot2_attack_onset_trajectory.png)
3. **Benign vs Attack Distribution**:
   [`plot3_benign_vs_attack_distribution.png`](file:///c:/Users/ayush/sih1/artifacts/experiments/future_security_risk_validation_v1/figures/plot3_benign_vs_attack_distribution.png)
4. **Risk Difference / Slope Around Onset**:
   [`plot4_risk_difference_slope.png`](file:///c:/Users/ayush/sih1/artifacts/experiments/future_security_risk_validation_v1/figures/plot4_risk_difference_slope.png)
5. **Horizon Comparison ($h=0..3$)**:
   [`plot5_horizon_comparison.png`](file:///c:/Users/ayush/sih1/artifacts/experiments/future_security_risk_validation_v1/figures/plot5_horizon_comparison.png)
6. **Contradiction & Termination Dynamics**:
   [`plot6_contradiction_termination.png`](file:///c:/Users/ayush/sih1/artifacts/experiments/future_security_risk_validation_v1/figures/plot6_contradiction_termination.png)

---

## 4. Automated Test Results

Executed complete regression suite:
```powershell
$env:PYTHONPATH="."
python -m pytest tests/test_future_security_risk_validation.py tests/test_future_security_risk.py tests/test_statistical_hardening.py tests/test_final_evidence.py -v
```
**Outcome**: **43 passed in 1.94s** (100% pass rate, zero regressions, zero test weakening).
