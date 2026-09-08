# Decision Log

## 2026-08-29 — Day-1 contract implementation

Implemented the reviewed frozen interfaces as Python dataclasses with validation. No interface fields were removed or redefined. Group-level trajectory weight normalization and configured threshold enforcement are deferred to their owning future components; the interface prevents invalid individual weights and missing prune explanations.

## 2026-08-29 — Placeholder policy

The synthetic pipeline uses zero deltas solely to verify wiring. It labels its model `DAY1_PLACEHOLDER`, emits `INSUFFICIENT` trust and `Unknown` stage, and produces reversible escalation-only recommendations. This is not a model prediction or probability estimate.

## 2026-08-29 — Pending human decision: Day-2 CIC flow schema incompatibility

The available CIC-IDS2018 Wednesday and Thursday flow CSVs contain 80 columns but do not contain `Src IP`, `Dst IP`, or `Src Port`; they contain only `Dst Port`. Consequently the frozen required `NetworkState` fields `src_ip_diversity`, `dst_ip_diversity`, `src_port_diversity`, `fan_out`, `internal_ratio`, and `east_west_count` cannot be truthfully derived from these sources.

Additionally, Day-2 instructions require `internal_ratio` and `east_west_count` to be unavailable/null when no deterministic internal-address mapping is defined, whereas the frozen contract currently makes them required non-null numeric fields. The current data contract defines no internal-address mapping.

No ingestion code or contract change has been made. Human approval is required to choose one of: provide compatible raw flow files and an approved address mapping; amend the frozen contract to represent unavailable topology fields; or explicitly approve a documented missingness representation without treating it as a measured value.

## 2026-08-29 — Approved Day-2 observability extension

Human approval received: endpoint-dependent topology fields are nullable with typed availability. For the current CIC CSV source they are `UNAVAILABLE`, never zero-filled or imputed; data quality remains independent. The same schema can later mark those fields `AVAILABLE` for PCAP or merged telemetry. Labels remain diagnostic-only and are not read into `NetworkState` or predictive features.

## 2026-08-29 — Day-2 NaN/Inf feature-level missingness policy

Preserve usable flow telemetry when individual numeric values are NaN/Inf. Flows are retained in their corresponding time windows as long as the timestamp is valid and parseable. Individual NaN/Inf fields are mapped to explicit missingness (`None`) without discarding the entire row or fabricating values. Window aggregation ignores missing values when calculating means/stds/rates; if an aggregate has zero valid observations, it is marked `UNAVAILABLE` in `feature_availability` and omitted from `feature_values()`. Cleaning statistics explicitly track `nan_values_seen`, `inf_values_seen`, and `rows_with_invalid_numeric_values` separately from unrecoverable row removals.

## 2026-08-29 — Day-3 Delta-State Baseline Experiment Execution & Gate Evaluation

Executed the first major ML feasibility gate on real Wednesday and Thursday CIC state artifacts (6,766 contiguous $h=3$ transitions). All 10 anti-leakage sanity checks passed.
Evaluated frozen baseline ladder: B1 (Zero-Change), B2 (Persistence), B3 (EWMA), B4 (AR-style), B5 (Ridge), B6 (GBDT).
Key outcome:
1. Directional signal is robust: Learned models and AR-style achieve 62%–68% directional accuracy across features, significantly outperforming Zero-Change (2.1%) and Persistence/EWMA (~33%).
2. High-variance features (e.g. `byte_variance`) exhibit wide scale shifts, making AR-style per-feature models achieve lower raw MAE than full-history models.
3. Victory Criterion: Gate returns **YELLOW / RED** against the frozen criterion requiring simultaneous raw MAE and DA wins across >=3/4 folds. Proves short-horizon network-state transition structure exists (directional signal), but does NOT justify complex final world models without feature normalization/scaling in the loss formulation.

## 2026-08-29 — Day-4 Delta-State Baseline V2 Normalization & AR Memory Sensitivity Decisions

1. **Audit & Scale Normalization:** Audit confirmed that raw unscaled global MAE in v1 was >99.99% driven by `byte_variance`. Robust scale normalization ($s_j = \text{IQR}(y_{\text{train}, j})$) fit strictly on training targets provides fair, unbiased multi-feature evaluation.
2. **Configuration Semantics & Context Distinction:**
   - Explicitly distinguished `state_history_depth` from `ar_lag_order`: AR(5) requires six consecutive states (`state_history_depth = 6`) to extract five contiguous historical deltas (`ar_lag_order = 5`).
   - Recorded that `delta_baseline_v2` used `history_depth = 6` with AR sensitivity $p = 1\dots 5$. V2 is therefore a combined *scale normalization + temporal-context sensitivity* experiment, not a pure normalization-only ablation.
   - Enforced an invariant configuration test ensuring AR(5) cannot silently execute on fewer than six consecutive states ($<5$ historical deltas).
3. **Operational Forecasting vs Evaluation Protocols:**
   - Defined `operational forecasting = strictly forward-in-time context` where all feature and delta histories strictly precede the forecasted target in time without cross-boundary contamination.
   - Distinguished this from `leave-one-infiltration-block-out generalization = a separate evaluation protocol` designed to evaluate out-of-block generalization across observed attack periods.
## 2026-08-29 — Day-5 Multi-Step Rollout & Uncertainty Quantification Decisions (Corrected)

1. **Multi-Step Rollout Dynamics & Semantic Labeling:**
   - **True Open-Loop Multi-Step Rollout:** Recursive multi-step forecast evaluated without future ground truth. Directional accuracy degrades from $68.09\%$ at $h=1$ to $50.95\%$ at $h=2$ and $50.21\%$ at $h=3$, confirming open-loop predictive power degrades toward random walk within 10–20 seconds.
   - **Rolling One-Step After Refresh:** Repeated one-step forecast after true observation refresh, maintaining steady $\approx 68.1\%$ directional accuracy. Explicitly documented that this does *not* establish 20s/30s open predictive accuracy.
2. **Empirical Residual Bootstrap Formulation & Calibration:**
   - Constructed joint residual pool $E_{\text{train}} \in \mathbb{R}^{N_{\text{train}} \times D}$ strictly from training predictions to preserve cross-feature correlation.
   - Marginal per-feature empirical prediction intervals achieved accurate coverage on held-out test data (80% nominal $\to 81.9\%\text{--}84.1\%$; 90% nominal $\to 89.7\%\text{--}91.2\%$; 95% nominal $\to 93.9\%\text{--}94.9\%$).
3. **True Empirical Scenario Trajectory Construction ($K=3$):**
   - Constructed $K=3$ scenario trajectories ($T_0$ deterministic, $T_1$ empirical-upper, $T_2$ empirical-lower) from single continuous bootstrap simulation paths based on trajectory-level deviation scores, preserving cross-feature and cross-horizon covariance.
   - Documented weights ($0.50, 0.25, 0.25$) as scenario-display weights rather than calibrated probabilities.
4. **Trust Degradation & Reconsideration:**
   - Trust assessment accurately models forecast horizon uncertainty decay ($h=1: 0.20 \to h=2: 0.08 \to h=3: 0.05$).
   - Validated the dynamic reconsideration mechanism: receiving deviating telemetry updates context, alters subsequent trajectory forecasts, and triggers trajectory re-ranking.
5. **Gate Classification:** **YELLOW** (Validates the receding-horizon forecasting and uncertainty quantification foundation; open-loop horizon is constrained to short 1–2 step horizons).
## 2026-08-29 — Day-6A Behavioral Security Bridge Decisions

1. **Deterministic Behavioral Signatures:**
   - Implemented explainable signatures using only available CSV telemetry: Reconnaissance/port exploration, Connection flooding/resource pressure, Exfiltration outbound surge, and Timing anomaly.
   - Strictly marked Lateral Fan-out as `UNAVAILABLE` due to missing endpoint IP telemetry, avoiding fabricated topological indicators.
2. **Current vs Forecasted Evidence Separation:**
   - Signatures explicitly distinguish between currently observed conditions ($h=0$) and forecasted trajectory evolution ($h=1, 2, 3$).
3. **Stage Hypotheses with Counter-Evidence & Alternatives:**
   - Hypotheses explicitly include counter-evidence and benign alternative explanations (e.g., service discovery, routine backup, user load spikes).
   - `Unknown` is preserved as an active, first-class hypothesis whenever telemetry is insufficient or within baseline parameters.
4. **ATT&CK Mapping Decoupling:**
   - ATT&CK techniques (`T1046`, `T1498`, `T1048`, `T1071`) are maintained as a separate explanatory mapping layer with documented limitations, rather than an ML classification target.
5. **Gate Classification:** **YELLOW** (Behavioral security bridge operates with strict explainability, counter-evidence, and uncertainty awareness; multi-step forecast escalation is technically verified).

## 2026-08-29 — Day-6B Behavioral Security Bridge Validation Decisions

1. **Controlled Behavioral Discrimination Validation:**
   - Tested 6 synthetic traffic fixtures representing distinct network behaviors: Benign Baseline, Port Exploration, Connection Flooding, Outbound Surge, Timing Anomaly, and Ambiguous Mixed Traffic.
   - Proved that the Behavioral Security Bridge maps disparate telemetry profiles to distinct primary stages and signatures, successfully passing the Anti-Stage-Collapse gate (`PASS`).
2. **Forecast Reinforcement & Contradictory Forecast Handling:**
   - Demonstrated that consistent forecasted growth escalates stage hypothesis confidence, validating the predictive escalation mechanism.
   - Demonstrated that a contradictory forecast (predicting sudden collapse / return to baseline) suppresses confidence and attaches explicit counter-evidence, proving the system does not blindly escalate.
3. **Abstention & UNKNOWN Preservation:**
   - Verified that benign baselines abstain to `Unknown` ($\text{Conf}=0.85$) and ambiguous cases produce competing hypotheses with capped confidence ($\le 0.55$), ensuring zero false certainty.
4. **Gate Classification:** **GREEN** (Controlled behavioral discrimination, anti-stage-collapse, and forecast sensitivity validated).

## 2026-08-29 — Day-7 Operational Decision Layer Decisions

1. **Multidimensional Priority Assessment:**
   - Explicitly decoupled consequence, likelihood, asset criticality, proximity, and actionability into separate scores within `PriorityAssessment`.
   - Invariant: High model uncertainty / low trust severely dampens composite priority score, preventing false CRITICAL escalation on speculative forecasts.
2. **Deterministic Role Relevance Routing:**
   - Defined configurable `RoleProfile` instances for `SOC_ANALYST`, `NETWORK_DEFENDER`, `INCIDENT_COMMANDER`, `DATA_PROTECTION`, and `ENDPOINT_ANALYST`.
   - Invariant: Alerts route strictly to relevant roles; non-relevant roles are assigned `RelevanceStatus.NOT_RELEVANT` and receive zero notifications.
3. **Role Context Differentiation & Suppression:**
   - The same security event produces distinct, tailored headlines, context, and next actions for different operational roles.
   - Built a deterministic deduplication cache that suppresses duplicate alerts on unshifted telemetry while dispatching immediate updates upon material forecast/trust shifts.
4. **Strict Human-Gated Response Recommendations:**
   - All response recommendations enforce `requires_human=True` and `is_reversible=True`.
   - Low-trust and UNKNOWN scenarios default to observation and telemetry collection (`INCREASE_MONITORING`, `ADDITIONAL_INSPECTION`).
   - The system strictly possesses zero capability or interface for autonomous action execution.
5. **Gate Classification:** **GREEN** (Decision layer is safe, explainable, human-gated, and role-differentiated).

## 2026-08-29 — Day-8 Live Telemetry Demo & Controlled Attack Replay Decisions

1. **Deterministic Scenario Replay Engine:**
   - Built a controlled telemetry replay engine emitting timestamped, schema-compliant `NetworkState` sequences across 5 canonical scenarios (`demo_recon_15s`, `demo_recon`, `demo_dos`, `demo_exfiltration`, `demo_ambiguous`).
   - Invariant: Zero raw packet capture or sniffing invented; telemetry enters strictly through the validated `NetworkState` pipeline with zero label or attack metadata leakage.
2. **Reconsideration Loop Validation:**
   - The canonical 15-second timeline proves that when telemetry contradicts a forecast (e.g. abrupt probe cessation at $T_8$), model trust decays, confidence is suppressed ($0.85 \to 0.40$), and priority drops (`MEDIUM` $\to$ `INFO`), avoiding alarm fatigue.
3. **Role-Selective Live Feed:**
   - Invariant: Not everyone receives the alert. Relevant roles (`SOC_ANALYST`, `NETWORK_DEFENDER`) receive customized headlines and details; non-relevant roles (`ENDPOINT_ANALYST`, `DATA_PROTECTION`) receive zero notifications.
4. **Strict Human-in-the-Loop Constraint:**
   - 100% of demo events produce reversible recommendations requiring explicit human approval (`requires_human=True`).
   - The system strictly possesses zero capability or interface for automated destructive actions.
5. **Gate Classification:** **GREEN** (Full intelligence stack executes end-to-end deterministically and safely).

## 2026-08-29 — Day-9 Useful Response Window Experiment Decisions

1. **Comparable Event & Alert Definitions:**
   - Established frozen, objective sustained event definitions $E$ (e.g. $D_{\text{port}} \ge 20$ for $\ge 2$ consecutive windows) evaluated identically across Conventional Current-State, Logistic Regression, and Predictive detectors.
2. **Deterministic A/B Simulated Response Window:**
   - Modeled reversible defender preparation actions with explicit 20s execution durations (`REVIEW_BOUNDARY_ACLS`, `PREPARE_RATE_LIMIT`, `PREPARE_EGRESS_RESTRICTION`).
   - Empirical Finding: Predictive forecasting triggered 10s earlier at $w=4$, enabling Defender B to complete preparation at $60\text{s}$ before sustained onset ($w=6$), while Defender A (alerted at $w=5$) finished at $70\text{s}$ (post-sustained onset).
3. **Equal Alert Budget / False-Positive Fairness:**
   - Verified that Predictive Trajectory Detector generates $0$ false positives on transient benign bursts and ambiguous background noise, matching the Conventional Current-State baseline.
## 2026-08-29 — Day 9B: AR(3) vs AR(5) Operational Availability & Trade-Off Policy (Recommendation C)

1. **Context & Motivation:**
   - Evaluated whether AR(5)'s higher context requirement (6 consecutive states / 5 historical deltas) incurs unacceptable forecast availability loss relative to AR(3) (4 consecutive states / 3 historical deltas) on real telemetry streams with gaps and empty windows.
2. **Empirical Findings Across 8,640 Real States:**
   - **Availability Loss:** Only **0.29%** overall (6,752 valid forecasts for AR(3) vs 6,727 for AR(5); 25 states lost out of 8,640).
   - **Attack Window Continuity:** Inside all 4 observed infiltration blocks, AR(5) lost **0 valid forecasts** (343/343, 445/445, 577/577, 343/343) because telemetry during active operations is dense and continuous.
   - **Accuracy Advantage:** AR(5) consistently delivers +1.84% directional accuracy on the chronological test split (68.64% vs 66.80%) and up to +2.8% inside active infiltration blocks.
   - **Demo Path Continuity:** In the canonical 16-step demo (`demo_recon_15s`), baseline warmup ($w00\dots w04$) populates AR(5) before attack onset ($w06$), causing zero forecast dropouts.
3. **Policy Decision:** **Recommendation C**
   - Retain AR(5) as the primary dynamics core.
   - Support architectural fallback to AR(3) when 5 historical deltas are unavailable due to recent telemetry gaps.
4. **Gate Classification:** **GREEN** (AR(5) retention is empirically validated; temporal continuity trade-off is minor and non-impairing).

## 2026-08-29 — Day 10: Mathematically Grounded Explainability Architecture & Feature Contribution Validation

1. **Context & Motivation:**
   - Security analysts, incident responders, and network operators require transparent, defensible explanations for why the dynamics model predicted specific transitions and why the behavioural security bridge strengthened or weakened specific stage hypotheses.
   - Ground truth rule: Explanations must be derived strictly from the underlying autoregressive model coefficients, telemetry feature distributions, and behavioural signature thresholds. Generative LLMs are explicitly prohibited from fabricating post-hoc explanations.
2. **Architectural Decisions & Implementation:**
   - **Typed Explainability Contracts (`explainability/contracts.py`):** Established strictly typed, frozen dataclasses (`ForecastExplanation`, `FeatureContribution`, `LagContribution`, `SecurityHypothesisExplanation`) capturing provenance hashes, evidence types (`CURRENT`, `FORECAST`, `BOTH`), signed directions (`POSITIVE`, `NEGATIVE`, `NEUTRAL`), and normalized relative contribution weights.
   - **Mathematical Lag Decomposition (`explainability/engine.py`):** For AR(5) forecasts $\Delta \hat{x}_j(t+1) = c_j + \sum_{l=1}^5 \beta_{j, l} \Delta x_j(t - l + 1)$, computed exact signed lag contributions $C_{j, l} = \beta_{j, l} \Delta x_j(t - l + 1)$ and percentage lag weights.
   - **Scale-Normalized Multi-Feature Ranking:** Feature contributions are normalized against the training distribution interquartile range ($\text{IQR}(y_{\text{train}, j})$) to prevent high-magnitude features (e.g. byte volume) from drowning out discrete structural features (e.g. destination port diversity, SYN/RST ratios).
   - **Mandatory Evidence Scope Discrimination:** Explanations strictly partition whether evidence comes from an already observed elevation (`CURRENT`), projected future momentum (`FORECAST`), or mutual reinforcement (`BOTH`).
   - **Controlled Input Perturbation Engine:** Validated model explanation response directionality across controlled synthetic fixtures (Reconnaissance $+0.30$, DoS $+0.85$, Exfiltration $+0.80$).
   - **Safety & Epistemic Humility Invariants:** Unavailable topology features (`fan_out`, internal ratios) are strictly masked as unavailable; ground-truth labels and attack fraction are prevented from leaking; all narrative text uses objective statistical language ("model contribution") avoiding ungrounded global causal assertions.
3. **Gate Classification:** **GREEN** (Explainability layer is mathematically rigorous, fully operational, deterministic, and passing 100% of validation tests).

## 2026-08-29 — Step 2B: Bounded Future Security-Risk Score R(t+h) vs Calibrated Attack Probability

1. **Context & Motivation:**
   - SIH Problem Statement 26153 references anticipating future infiltration probability over upcoming observation windows.
   - Scientific constraint: In network intrusion datasets where attacks are sparse, episodic, non-stationary, and structurally shift between days, asserting a calibrated Bayesian posterior probability $P(\text{Attack} \mid \dots)$ constitutes epistemic overreach that fails calibration and validation checks.
   - Solution: Implement a mathematically bounded, deterministic **Future Security-Risk Score** $R(t+h) \in [0.0, 1.0]$ for horizons $h \in \{0, 1, 2, 3\}$ (representing NOW, +10s, +20s, +30s), explicitly defined as the *relative security-risk intensity of the predicted behavioural trajectory under current evidence and model trust*.

2. **Mathematical Formulation & Core Invariants:**
   - Formula:
     $$R(t+h) = \text{clip}\left( \text{Severity}(t+h) \times \text{Confidence}_{\text{stage}}(t+h) \times \text{Trust}(t+h) \times (1 - \text{Uncertainty}(t+h)) \times 1.50, \, 0.0, \, 1.0 \right)$$
   - Stage Severity: $\text{Impact} = 0.85$, $\text{Exfiltration} = 0.80$, $\text{Initial Access} = 0.60$, $\text{Reconnaissance} = 0.40$, $\text{Unknown} = 0.15$.
   - Boundedness: $0.0 \le R(t+h) \le 1.0$ under all inputs.
   - Horizon Uncertainty Decay: Uncertainty increases with open-loop lookahead ($U_0=0.10 \to U_1=0.20 \to U_2=0.35 \to U_3=0.50$), naturally moderating distant risk scores.
   - Contradiction Dampening: A contradictory forecast (predicting sudden drop in port diversity) degrades trust to LOW ($0.35$) and introduces counter-evidence, suppressing $R(t+1)$ from $0.35$ down to $0.03$.
   - Safety Invariant: High risk score combined with low model trust cannot escalate priority to `CRITICAL`.
   - Zero Label Leakage: Attack labels and infiltration fractions are strictly excluded.

3. **Gate Classification:** **GREEN** (Defensible, mathematically bounded, fully tested across 14 validation criteria with 100% pass rate).



