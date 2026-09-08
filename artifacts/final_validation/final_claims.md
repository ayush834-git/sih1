# SIH 26153 — Final Claim Strength & Boundary Matrix

This document defines the strict, authoritative epistemic boundaries for all claims, presentations, slide decks, demonstration scripts, and research writeups for SIH 26153.

Claims are categorized into three definitive tiers:
- **GREEN (Directly Supported):** Fully proven by persisted, reproducible experimental artifacts and test suites.
- **YELLOW (Supported with Stated Limitations):** Empirically verified under specific controlled conditions or simulated frameworks; must ALWAYS be accompanied by stated caveats.
- **RED (Prohibited / Must NOT be Claimed):** Unsupported, overextended, non-generalizable, or scientifically invalid claims.

---

## GREEN — Directly Supported Claims

| Claim Domain | Precise Allowed Wording | Supporting Persisted Artifact | Exact Metric / Evidence |
| :--- | :--- | :--- | :--- |
| **Short-Horizon Dynamics** | "Linear autoregressive dynamics models capture genuine short-horizon (10-second) directional predictive structure in windowed network telemetry." | `artifacts/experiments/delta_baseline_v2/` | AR(5) achieves **`68.10%`** directional accuracy on test split vs `2.11%` for ZeroChange and `32.89%` for Persistence. |
| **AR(5) Model Efficiency** | "AR(5) on historical deltas provides a robust, computationally lightweight dynamics core that outperforms simple moving averages and matches or exceeds regularized nonlinear models." | `artifacts/experiments/delta_baseline_v2/` | AR(5) achieves lower Median Normalized MAE (**`0.4052`**) than Persistence (`0.8000`), EWMA (`0.5212`), Ridge (`0.5081`), and GBDT (`0.5253`). |
| **Predictive Alert Lead Time** | "In controlled progression replays, predictive trajectory forecasting triggered an alert 10.0 seconds prior to conventional current-state threshold crossings." | `artifacts/experiments/response_window_v1/` | Predictive alert triggered at $w=4$ ($40\text{s}$) vs current-state alert at $w=5$ ($50\text{s}$) across 3 attack progressions (**`10.0s raw lead time`**). |
| **Receding Horizon Utility** | "Receding-horizon one-step forecasting retains actionable predictive accuracy when continuously refreshed with incoming telemetry observations." | `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/` | Observation-refreshed rolling forecasts sustain **`68.11%`** directional accuracy across consecutive time windows. |
| **Uncertainty Calibration** | "Training-only empirical residual bootstrap generates well-calibrated marginal prediction intervals for short-horizon state uncertainty." | `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/` | Observed test coverage at 90% nominal interval is **`89.71%`** (coverage error of only **`-0.29%`**). |
| **Behavioral Discrimination** | "The Behavioral Security Bridge deterministically maps macroscopic transport dynamics to distinct attack stage hypotheses with zero stage collapse." | `artifacts/experiments/security_bridge_validation_v1/` | **`100%` Anti-Stage-Collapse pass rate**; 5 distinct primary stages produced across 6 controlled fixtures. |
| **Clean UNKNOWN Abstention** | "The security bridge abstains cleanly to Unknown on benign baseline traffic and dampens confidence under contradictory telemetry." | `artifacts/experiments/security_bridge_validation_v1/` | Benign traffic produces `Unknown` primary stage ($\text{Conf}=0.85$); contradictory forecasts suppress confidence ($0.75 \to 0.40$). |
| **Role-Selective Alerting** | "Consequence-aware decision engine routes differentiated notifications strictly to relevant operational roles and suppresses duplicate spam." | `artifacts/experiments/decision_layer_v1/` | **`100%` spam suppression** on identical states; distinct headlines dispatched to SOC Analyst and Network Defender; Endpoint Analyst excluded on missing host data. |
| **Human-Gated Safety** | "All recommended defensive actions are strictly reversible and enforce mandatory human approval gates with zero autonomous destructive execution." | `artifacts/experiments/decision_layer_v1/` | **`13 / 13` safety invariants passed**; 100% of recommendations enforce `requires_human=True` and `is_reversible=True`. |
| **Mathematical Explainability** | "Forecast explanations are derived strictly from signed AR lag decomposition and scale-normalized feature distributions, avoiding LLM hallucinations." | `artifacts/experiments/explainability_v1/` | Perturbation tests confirm expected confidence response (Recon **`+0.30`**, DoS **`+0.85`**, Exfil **`+0.80`**); **`100%` deterministic idempotence**. |
| **AR Context Trade-off** | "AR(5) yields a +1.84% accuracy gain over AR(3) while losing zero valid forecasts across active attack periods." | `artifacts/experiments/ar_order_availability_v1/` | AR(5) achieves **`68.64%`** vs AR(3) **`66.80%`**; **`0`** forecasts lost in all 4 attack blocks; **`0.29%`** global loss rate. |
| **Future Security-Risk Index** | "The system produces bounded, explainable future security-risk scores R(t+h) across NOW, +10s, +20s, and +30s that scale under attack momentum and dampen under contradictory forecasts." | `artifacts/experiments/future_security_risk_v1/` | **`14/14` validation tests passed**; R(t+h) bounded in [0, 1]; contradiction dampens risk ($0.35 \to 0.03$). |
| **Statistical Hardening & Uncertainty** | "AR(5) directional accuracy is 68.10% [95% CI: 67.32%–68.87%], and AR(5) vs AR(3) gain is +0.82% [95% CI: +0.23%–+1.38%] on test, evaluated via dependency-aware moving block bootstrapping." | `artifacts/experiments/statistical_hardening_v1/` | Moving Block Bootstrap ($B=12$, $n_{\text{boot}}=2000$); McNemar $\chi^2 = 13.24$, $p = 2.74 \times 10^{-4}$. |

---


## YELLOW — Supported Claims with Mandatory Caveats

| Claim Domain | Allowed Conditional Wording | Mandatory Caveat / Limitation | Source Artifact |
| :--- | :--- | :--- | :--- |
| **Useful Response-Window Gain** | "Predictive forecasting provided a simulated 10.0s useful response window gain, allowing a modeled 20s reversible preparation action to complete before sustained event onset." | **CAVEAT:** Action duration is simulated (fixed 20s execution model). Does NOT represent empirical human cognitive triage time in live enterprise SOC environments. | `artifacts/experiments/response_window_v1/` |
| **Attack-Stage Hypotheses** | "The system synthesizes candidate attack stage hypotheses (Reconnaissance, Impact/DoS, Collection/Exfiltration) from transport dynamics." | **CAVEAT:** Macroscopic flow features cannot observe application-layer payload semantics or encrypted command-and-control channels. | `artifacts/experiments/security_bridge_v1/` |
| **Multi-Step Forecasting** | "Multi-step forecasting provides scenario trajectories under receding-horizon observation ingestion." | **CAVEAT:** True unrefreshed open-loop recursive projections degrade to near chance within 20–30s ($h=2: 50.95\%, h=3: 50.21\%$). System requires continuous observation refresh. | `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/` |
| **Future Risk Index Semantics** | "Future security-risk scores R(t+h) capture the relative risk intensity of the predicted behavioural trajectory across 10s–30s windows." | **CAVEAT:** R(t+h) is an uncalibrated composite risk intensity index, NOT a calibrated Bayesian posterior probability of attack. | `artifacts/experiments/future_security_risk_v1/` |
| **Scenario Trajectory Weights** | "The system displays K=3 plausible scenario paths (deterministic, empirical-upper, empirical-lower) with normalized scenario weights (0.50, 0.25, 0.25)." | **CAVEAT:** Weights are scenario display weights derived from bootstrap trajectory rank, not calibrated joint Bayesian posterior probabilities. | `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/` |
| **MITRE ATT&CK Mapping** | "Hypotheses are associated with candidate ATT&CK techniques (T1046, T1498, T1048, T1071) as an explanatory bridge." | **CAVEAT:** Technique mapping is an explainability heuristic layer, not a supervised classification model. | `artifacts/experiments/security_bridge_v1/` |
| **Dataset Representativeness** | "The pipeline is evaluated on 172,800 seconds (8,640 states) of CSE-CIC-IDS2018 benchmark telemetry." | **CAVEAT:** CSE-CIC-IDS2018 is a synthetic benchmark environment; production enterprise networks feature higher background diversity and host topology complexity. | `artifacts/state_sequences/` |

---

## RED — Prohibited Claims (Must NOT be Made)

| Prohibited Claim | Why It Is Prohibited | Proper Scientific Position |
| :--- | :--- | :--- |
| **"Universal attack prediction / Predicts all cyber attacks"** | Autoregressive models operate on transport-layer flow summary statistics. Zero-days operating via application payload logic, memory corruption, or encrypted channels cannot be forecasted from flow counts alone. | State clearly that the system forecasts short-term transitions in observable macroscopic transport telemetry. |
| **"Calibrated Bayesian Attack Probability / The system predicts a 0.82 probability of attack"** | Attacks are episodic and non-stationary; claiming calibrated probabilistic prediction constitutes unscientific overreach that fails calibration checks. | Describe R(t+h) as a *bounded future security-risk score or index*. |
| **"Proven reduction in real-world SOC response time / dwell time"** | Operational trials with human SOC analysts were not conducted. Response window gains were measured using fixed 20-second simulated preparation scripts in controlled replay. | State that the response window gain is a *controlled simulated result* demonstrating the theoretical benefit of 10s earlier alert delivery. |
| **"Calibrated joint probability distribution over future attacks"** | Residual bootstrap provides marginal per-feature uncertainty intervals ($D$ 1D intervals), not a calibrated joint probability distribution over the $D$-dimensional state space. | Present interval coverage as marginal per-feature uncertainty estimates. |
| **"Autonomous AI SOC / Fully automated defense"** | The system possesses zero interface or authority to execute destructive actions (such as firewall port blocking or host isolation). All recommendations require explicit human approval. | State that the system is an *analyst decision-support and proactive preparation system*. |
| **"Live wire-speed 100Gbps kernel packet capture sniffer"** | Telemetry enters as discretized `NetworkState` objects from NetFlow CSV records or controlled replay. No raw kernel C/eBPF packet sniffer exists in this codebase. | Accurately describe the ingest pipeline as operating on windowed NetFlow summary telemetry. |
| **"Long-horizon attack forecasting (30–60s) without telemetry"** | Open-loop recursive forecast accuracy drops to 50.21% at 30s. The system cannot reliably project attack progression over long horizons without incoming observations. | Emphasize *receding-horizon observation-anchored forecasting*. |
| **"Guaranteed zero-breach outcome in production enterprise networks"** | Defensive preparation actions reduce exposure window under modeled conditions, but cannot guarantee prevention of multi-vector advanced persistent threats. | Present the system as a risk-mitigation decision-support tool. |

---

## Enforcement Checklist for Presentations and Demos

- [x] Does every slide reporting a 10s response window gain mention "controlled simulated action model"?
- [x] Are AR(5) accuracy numbers reported as "directional accuracy" on scale-normalized delta transitions?
- [x] Are future risk numbers reported as "bounded future security-risk score" rather than "calibrated attack probability"?
- [x] Is human approval explicitly presented as mandatory for all defensive actions?

- [x] Is multi-step forecasting explicitly labeled as "receding-horizon with observation refresh"?
- [x] Are response actions described as "human-gated, reversible preparation recommendations"?
- [x] Are unobserved host topology features (`fan_out`, internal ratios) explicitly acknowledged as `UNAVAILABLE`?
- [x] Is all discussion of MITRE ATT&CK techniques framed as explanatory mapping rather than supervised classification?
