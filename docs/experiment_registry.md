# Experiment Registry

No experiments have been run on Day 1.

The synthetic smoke test is a software-structure check, not an experiment and has no model, dataset, metrics, or research conclusion.

## Day-2 data processing

No ML experiment is registered. State construction artifacts record source hashes, configuration, cleaning accounting, state counts, sessions, and artifact hashes. They are telemetry-preparation artifacts, not model results.

## Day-3 Experiment: delta_baseline_v1 (First Major ML Gate)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/delta_baseline_v1/`
- **Objective**: Test whether the corrected `NetworkState` representation contains predictive short-horizon $\Delta S$ structure against strong temporal baselines (B1-B6).
- **Datasets**:
  - Wednesday: `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.states.jsonl` (SHA: `8d9d6377...`, 4,320 states, 3,387 valid transitions)
  - Thursday: `Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl` (SHA: `ccff1948...`, 4,320 states, 3,379 valid transitions)
  - Total valid transitions: 6,766 ($h=3$, 15 available features).
- **Splits**:
  - Chronological (60% Train: 4,060, 15% Val: 1,015, 25% Test: 1,691).
  - Leave-One-Observed-Infiltration-Block-Out (4 folds: Wed 01:42-02:39, Wed 10:50-12:04, Thu 02:00-03:36, Thu 09:57-10:54).
- **Sanity Checks**: 10/10 Passed (0 label leakage, 0 infiltration_fraction, 0 gap/session crossing, train-only scaler fitting).
- **Findings**:
  - Directional Accuracy: Learned models (Ridge 64.7%, GBDT 62.4%) and AR-style (65.6%) drastically outperform Zero-Change (2.1%) and Persistence/EWMA (~33%).
  - Delta-MAE: AR-style and Zero-Change retain lower unscaled raw MAE than full unconstrained history models on high-variance features.
  - Frozen Victory Criterion: MIXED against Zero-Change/Persistence/EWMA (DA win, raw MAE loss); FAIL against AR-style.
- **Gate Recommendation**: YELLOW / RED.

## Day-4 Experiment: delta_baseline_v2 (Scale Normalization, Per-Feature Breakdown & AR Memory Sensitivity)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/delta_baseline_v2/`
- **Objective**: Determine whether the directional transition signal survives training-only per-feature scale normalization, evaluate AR memory order sensitivity ($p=1\dots 5$), and test whether learned nonlinear models provide advantage over AR on a fair normalized basis.
- **Datasets**:
  - Wednesday & Thursday CIC-IDS2018 `.states.jsonl` artifacts (identical hashes).
  - Total valid transitions: 6,727 ($h=6$ contiguous history).
- **Semantics & Evaluation Protocols**:
  - **Context Semantics:** Explicit distinction between `state_history_depth` ($h=6$) and `ar_lag_order` ($p=5$). AR(5) requires six consecutive states to construct five contiguous historical deltas. V2 is a combined *scale normalization + temporal-context sensitivity* experiment, not a pure normalization-only ablation.
  - **Operational Forecasting:** Defined as *strictly forward-in-time context*, where all inputs strictly precede targets without cross-boundary contamination.
  - **Leave-One-Infiltration-Block-Out:** A distinct evaluation protocol for assessing out-of-fold generalization across observed attack periods.
- **Audit Findings (Part A)**:
  - Confirmed: In v1, unscaled raw MAE was >99.99% dominated by `byte_variance` (raw MAE $\approx 7.8 \times 10^{10}$ vs other features $< 100$).
  - Per-feature robust scale normalization ($s_j = \text{IQR}(y_{\text{train}, j})$) successfully equalizes feature evaluation.
- **Key Findings**:
  - **RQ1 (Directional Robustness):** Directional accuracy is highly robust under scale normalization ($64.5\%\text{--}68.1\%$ for AR/Ridge/GBDT vs $2.1\%$ for Zero-Change and $30.2\%\text{--}32.9\%$ for Persistence/EWMA).
  - **RQ2 (Predictable Behavioural Subspaces):** Timing/IAT behavior (71.2% DA), RST behavior (66.8% DA), Ack dynamics (70.0% DA), Packet length dynamics (72.1%–72.7% DA), Port diversity (68.1% DA), and Flow Duration (71.1%–73.1% DA) carry strong, learnable temporal transitions across all folds.
  - **RQ3 (AR Memory Sensitivity):** Increasing lag order from $p=1$ to $p=5$ monotonically improves Directional Accuracy ($64.18\% \to 68.10\%$) and non-zero DA ($65.56\% \to 69.56\%$) while lowering RMSE.
  - **RQ4 (Model Comparison):** AR-best ($p=5$) achieves the lowest Median Normalized MAE ($0.4052$) and highest Directional Accuracy ($68.10\%$), outperforming Ridge ($0.5081$ / $65.91\%$) and GBDT ($0.5253$ / $64.49\%$). Furthermore, AR-best wins on Normalized MAE and DA across all 4 of 4 held-out infiltration blocks.
- **Gate Recommendation**: **YELLOW** (Predictive short-horizon transition physics is firmly established; AR-style dynamics is the validated, scientifically superior dynamics core for Day 5+ without unnecessary neural overhead).

## Day-5 Experiment: delta_rollout_uncertainty_v1_corrected (Multi-Step Rollout & Uncertainty Quantification)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/`
- **Objective**: Determine whether AR(5) supports multi-step future rollouts ($h=1, 2, 3$), quantify true open-loop recursive error compounding vs rolling one-step forecasting after observation refresh, evaluate training-only empirical residual bootstrap prediction intervals (80%, 90%, 95%), generate defensible $K=3$ scenario trajectories from actual continuous bootstrap paths, model trust degradation, and validate dynamic reconsideration.
- **Datasets**:
  - Wednesday & Thursday CIC-IDS2018 `.states.jsonl` artifacts (identical hashes).
  - Total valid contiguous multi-step samples: 6,703 ($h=6$ context, $H=3$ rollout, within-session, zero gaps).
- **Semantics & Distinctions**:
  - **Open-Loop Recursive Multi-Step Rollout:** True multi-step forecast without ground-truth access ($h=1 \approx 68.09\% \to h=2 \approx 50.95\% \to h=3 \approx 50.21\%$). Proves that open-loop forecasting degrades toward random walk beyond 10–20s.
  - **Rolling One-Step After Refresh:** Repeated one-step forecast after true observation refresh, maintaining $\approx 68.1\%$ accuracy. Explicitly does NOT establish 20s/30s open predictive accuracy.
  - **Empirical Scenario Trajectories ($K=3$):** Selected from single, continuous bootstrap simulation paths (T0 deterministic, T1 empirical-upper, T2 empirical-lower) preserving cross-feature and cross-horizon covariance; weights are scenario-display weights, not calibrated probabilities.
- **Key Findings**:
  - **1-Step Reproduction:** Fully reproduced v2 baseline (Norm MAE = 187.01, Median Norm MAE = 0.4041, DA = 68.09%, DA(nz) = 69.56%).
  - **Prediction Interval Coverage:** Marginal per-feature prediction intervals closely track nominal targets with minimal error (80% $\to 81.9\%$, 90% $\to 89.7\%$, 95% $\to 93.9\%$).
  - **Trust Degradation:** Monotonically decays with horizon lookahead ($h=1: 0.20 \to h=2: 0.08 \to h=3: 0.05$).
  - **Controlled Reconsideration:** Verified dynamic forecast adaptation upon observing deviating telemetry, triggering trajectory re-ranking.
  - **Held-Out Infiltration Blocks:** Replicated across all 4 observed infiltration blocks (Block 1: $h=1$ DA 67.9%, Block 2: 69.0%, Block 3: 70.3%, Block 4: 66.9%).
- **Gate Recommendation**: **YELLOW** (Validates the receding-horizon forecasting and uncertainty quantification foundation; open-loop horizon is constrained to short 1–2 step horizons).

## Day-6A Experiment: security_bridge_v1 (Behavioral Security Bridge)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/security_bridge_v1/`
- **Objective**: Build and validate the Behavioral Security Bridge translating current network states and multi-step forecasted delta evolution into explainable behavioural signatures, stage hypotheses with counter-evidence and alternative benign explanations, and candidate MITRE ATT&CK technique mappings.
- **Key Findings**:
  - **Reliable Signatures:** Reconnaissance / port exploration (`dst_port_diversity`, `flow_count`, `syn_ratio`), Connection flooding / resource pressure (`flow_count`, `rst_ratio`, `packet_rate`), Exfiltration-like outbound surge (`byte_rate`, `pkt_size_mean`), and Timing anomaly (`iat_mean`, `iat_std`).
  - **Unavailable Signatures:** Lateral movement / internal fan-out is explicitly marked `UNAVAILABLE` because host IP endpoints are absent from current flow telemetry.
  - **Current vs Forecast Evidence:** Successfully differentiates between current telemetry elevations and forecasted multi-step growth.
  - **Stage Hypotheses & Counter-Evidence:** Every hypothesis includes counter-evidence and explicit alternative explanations (e.g. administrative scanning, service backups, flash traffic).
  - **ATT&CK Mapping Layer:** Mapped to candidate techniques (`T1046 Network Service Discovery`, `T1498 Denial of Service`, `T1048 Exfiltration Over Alternative Protocol`, `T1071 Application Layer Protocol`) with explicit limitations. `T1021 Remote Services` is explicitly marked `UNAVAILABLE`.
  - **Four Observed Infiltration Blocks:** Replayed through the bridge, confirming persistent reconnaissance/discovery behavior in all 4 blocks without label leakage.
  - **Dynamic Reconsideration:** Verified that new deviating observations update forecasts and re-rank stage hypotheses in real time.
- **Gate Recommendation**: **YELLOW** (Behavioral security bridge operates with strict explainability, counter-evidence, and uncertainty awareness; multi-step forecast escalation is technically verified).

## Day-6B Experiment: security_bridge_validation_v1 (Controlled Behavioral Discrimination Validation)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/security_bridge_validation_v1/`
- **Objective**: Execute a controlled, deterministic behavioural-discrimination validation of the Behavioral Security Bridge across 6 distinct synthetic traffic fixtures (Benign Baseline, Port Exploration / Recon, Connection Flooding / Resource Pressure, Sustained Outbound Surge / Exfiltration, Timing Anomaly, Ambiguous Mixed Traffic) to verify discrimination, anti-stage-collapse, forecast reinforcement, contradictory forecast suppression, and UNKNOWN abstention.
- **Key Findings**:
  - **Behavioral Discrimination:**
    - `1_benign_baseline` $\to$ Primary Stage: `Unknown` ($\text{Conf}=0.85$), zero active attack signatures.
    - `2_port_exploration` $\to$ Primary Stage: `Reconnaissance` ($\text{Conf}=0.75$), Signature: `RECONNAISSANCE_PORT_EXPLORATION`.
    - `3_connection_flooding` $\to$ Primary Stage: `Impact / Denial of Service` ($\text{Conf}=0.70$), Signature: `CONNECTION_FLOODING_RESOURCE_PRESSURE`.
    - `4_sustained_outbound_surge` $\to$ Primary Stage: `Collection / Exfiltration` ($\text{Conf}=0.65$), Signature: `EXFILTRATION_OUTBOUND_SURGE`.
    - `5_timing_anomaly` $\to$ Primary Stage: `Initial Access / Delivery` ($\text{Conf}=0.40$), Signature: `TIMING_BEHAVIOURAL_ANOMALY`.
    - `6_ambiguous_mixed` $\to$ Produces multiple mild competing hypotheses without unjustified certainty ($\text{Conf}=0.55$) and preserves `Unknown`.
  - **Anti-Stage-Collapse:** **PASS** (5 distinct primary stages produced across 6 fixtures; bridge is demonstrably NOT a mono-stage Recon detector).
  - **Forecast Reinforcement & Contradiction:**
    - Consistent forecast growth escalates confidence (Recon: $0.55 \to 0.85$; Exfil: $0.45 \to 0.80$).
    - Contradictory forecast predicting deceleration suppresses confidence ($0.75 \to 0.40$), adding explicit counter-evidence and preventing blind escalation.
  - **Unknown / Abstention:** Abstains cleanly on benign traffic and preserves `Unknown` as a candidate across all fixtures.
  - **MITRE ATT&CK Mapping:** Explicit candidate mappings (`T1046`, `T1498`, `T1048`, `T1071`) generated with documented limitations.
- **Gate Recommendation**: **GREEN** (The Behavioral Security Bridge exhibits robust, explainable behavioural discrimination, handles forecast reinforcement and contradiction appropriately, and passes all anti-stage-collapse checks).

## Day-7 Experiment: decision_layer_v1 (Priority Assessment, Role Routing & Human-Gated Response)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/decision_layer_v1/`
- **Objective**: Build and validate the Operational Decision Layer integrating multidimensional Priority Assessment (explicitly separating confidence, trust, consequence, proximity, and actionability), Deterministic Role-Relevance Routing, Role-Differentiated Notifications with suppression/update logic, and strictly Reversible, Human-Gated Response Recommendations.
- **Key Findings**:
  - **Priority Assessment:** Separates consequence, likelihood, asset criticality, proximity, and actionability. High uncertainty / low trust severely dampens composite priority (e.g. from MEDIUM to INFO), preventing speculative escalation.
  - **Deterministic Role Routing:** Dispatches alerts strictly to relevant roles based on operational profiles:
    - Benign/Unknown $\to$ 0 notifications dispatched (clean abstention).
    - Reconnaissance $\to$ `SOC_ANALYST`, `NETWORK_DEFENDER` (Endpoint Analyst omitted due to unavailable host telemetry).
    - Exfiltration Surge $\to$ `SOC_ANALYST`, `NETWORK_DEFENDER`, `DATA_PROTECTION`.
  - **Role-Differentiated Notifications:** Generates role-tailored headlines, contextual details, and next actions answering *Why am I being told this? What changed? What is expected next? How trustworthy is the forecast? What should I consider doing?*
  - **Suppression & Update Logic:** Identical duplicate states generate zero spam notifications; material telemetry shifts or trust adjustments trigger clean updates.
  - **Human-Gated Response Recommendations:** 100% of recommendations set `requires_human=True` and `is_reversible=True` (e.g. `INCREASE_MONITORING`, `ADDITIONAL_INSPECTION`, `RATE_LIMIT`). Zero automated destructive execution is possible.
  - **Safety Invariants:** 13/13 critical safety invariants passed.
- **Gate Recommendation**: **GREEN** (Operational decision layer operates safely, deterministically, with complete human-gating and strict role filtering).

## Day-8 Experiment: demo_validation_v1 (Live Telemetry Demo & Controlled Attack Replay)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/demo_validation_v1/` & `artifacts/demo/`
- **Objective**: Build and validate an end-to-end controlled real-time telemetry demonstration harness exercising the full intelligence stack (`NetworkState` $\to$ `AR(5)` dynamics $\to$ `BehavioralSecurityBridge` $\to$ `PriorityEngine` $\to$ `RoleRelevanceEngine` $\to$ `NotificationEngine` $\to$ `ResponseRecommendationEngine`).
- **Key Findings**:
  - **End-to-End Integrity:** Simulated/replayed telemetry enters strictly as schema-compliant `NetworkState` objects with zero attack labels or metadata leakage.
  - **15-Second Canonical Demo (`demo_recon_15s`):** Demonstrates baseline $T_0$, subtle deviation $T_1$, port exploration $T_2$, forecast reinforcement $T_3$, hypothesis upgrade $T_4$, priority rise $T_5$, selective role routing $T_6$ (`SOC` & `Network Defender` notified; `Endpoint Analyst` & `Data Protection` excluded), forecast contradiction $T_9$, trust decay $T_{10}$, priority dampening $T_{11}$ (`MEDIUM` $\to$ `INFO`), de-escalation update $T_{12}$, and human-gated recommendation $T_{14}$ (`requires_human=True`, `is_reversible=True`).
  - **Deterministic Replay:** Fixed seed ($42$) and `--no-sleep` mode reproduce identical logical event sequences.
  - **Safety Invariants:** 15/15 validation tests passed. Zero automated action execution; zero external network operations.
- **Gate Recommendation**: **GREEN** (Full intelligence stack executes smoothly and deterministically end-to-end with verified role isolation and human-in-the-loop safety).

## Day-9 Experiment: response_window_v1 (Predictive vs Current-State Detection: Useful Response Window)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/response_window_v1/`
- **Objective**: Empirically evaluate whether predictive trajectory forecasting provides a measurable, useful response window gain over conventional current-state threshold detectors and supervised Logistic Regression baselines under frozen, identical event definitions.
- **Key Findings**:
  - **Identical Ground-Truth Event Definitions:** Defined objective, observable sustained security conditions (e.g. $D_{\text{port}} \ge 20$ for $\ge 2$ consecutive 10s windows).
  - **Raw Lead Time:** Across 3 controlled attack progressions (`recon_progression`, `dos_progression`, `exfiltration_progression`), predictive forecasting alerted at $w=4$ ($40\text{s}$) projecting continuation, whereas current-state detectors alerted at $w=5$ ($50\text{s}$) only upon crossing threshold, yielding an average raw lead time of **$10.0\text{s}$** ($1$ full observation window).
  - **Simulated Useful Response Window:** Modeled a 20s reversible defender preparation action (e.g. `REVIEW_BOUNDARY_ACLS`, `PREPARE_RATE_LIMIT`, `PREPARE_EGRESS_RESTRICTION`). Defender B (predictive alert at $40\text{s}$) completed action at $60\text{s}$ (prior to sustained event onset at $w=6$ / $60\text{s}$). Defender A (current-state alert at $50\text{s}$) completed action at $70\text{s}$ ($10\text{s}$ late / post-sustained onset). Validated useful window gain = **$10.0\text{s}$**.
  - **False Positive Fairness:** On transient benign burst traffic and ambiguous background noise, both Conventional Current-State and Predictive detectors produced **$0$ false positives**.
  - **Safety & Methodological Invariants:** 13/13 validation tests passed. Zero label leakage; identical action execution models; deterministic replay.
- **Gate Recommendation**: **GREEN** (Predictive forecasting demonstrably buys the defender a useful 10-second preparation window across controlled attack progressions without inflating false positives).

## Day-9B Experiment: ar_order_availability_v1 (AR(3) vs AR(5) Operational Availability & Trade-Off Audit)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/ar_order_availability_v1/`
- **Objective**: Empirically evaluate the operational trade-off between AR(3) ($h=4$) and AR(5) ($h=6$) across 8,640 real NetworkState timeline positions, measuring directional accuracy gain vs forecast availability loss, security-critical block retention, and demo path continuity.
- **Key Findings**:
  - **Overall Availability:** AR(3) produces 6,752 valid forecasts (78.15% availability); AR(5) produces 6,727 valid forecasts (77.86% availability). Availability loss from AR(3) to AR(5) is **only 0.29%** (25 total state transitions lost out of 8,640).
  - **Infiltration Block Availability:** Across all 4 observed infiltration blocks, AR(5) lost **0 valid forecasts** relative to AR(3) (Block 1: 343 vs 343, Block 2: 445 vs 445, Block 3: 577 vs 577, Block 4: 343 vs 343).
  - **Directional Accuracy:** AR(5) consistently outperforms AR(3) across all evaluation cuts (+1.84% on Wed test: 68.64% vs 66.80%; +1.62% on Thu test: 68.22% vs 66.60%; +2.8% on Block 1; +1.6% on Block 2; +2.1% on Block 3; +0.9% on Block 4).
  - **Demo Relevance:** The canonical 16-step demo (`demo_recon_15s`) includes a 5-window baseline warmup ($w00\dots w04$), ensuring AR(5) is fully populated and active at $w05$ prior to port exploration at $w06$.
  - **Policy Decision:** **Recommendation C** (AR(5) remains the primary dynamics core due to superior accuracy and zero loss in sustained attack blocks, with an architectural fallback to AR(3) when 5-delta history is unavailable).
- **Gate Recommendation**: **GREEN** (AR(5) retention is empirically justified; availability cost is negligible within attack windows).


## Day-10 Experiment: explainability_v1 (Explainability & Feature-Contribution Validation)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/explainability_v1/`
- **Objective**: Build and validate a mathematically grounded, non-LLM explainability layer answering *why* the system forecast specific state transitions, *why* behavioural security signatures activated, and *which features contributed in which direction*, distinguishing current observed changes from predicted forward momentum.
- **Key Findings**:
  - **Mathematical Lag Decomposition:** For each autoregressive forecast $\Delta \hat{x}_j(t+1) = c_j + \sum_{l=1}^5 \beta_{j, l} \Delta x_j(t - l + 1)$, signed lag contributions $C_{j, l} = \beta_{j, l} \Delta x_j(t - l + 1)$ and relative lag weights were computed with zero heuristic drift or LLM hallucination.
  - **Scale-Normalized Feature Ranking:** Multi-feature rollout ranking normalized contributions against training feature spread ($\text{IQR}(y_{\text{train}, j})$), preventing high-magnitude byte scales from masking port diversity or ratio indicators.
  - **Controlled Perturbation Validation:** Evaluated 3 core hypotheses under controlled feature perturbation:
    1. *Reconnaissance* (`dst_port_diversity` $+5 \to +25$): confidence shifted $+0.30$ ($0.55 \to 0.85$, validated $\text{INCREASING}$).
    2. *Impact / DoS* (`flow_count + rst_ratio` $+50/0.05 \to +500/0.45$): confidence shifted $+0.85$ ($0.00 \to 0.85$, validated $\text{INCREASING}$).
    3. *Collection / Exfiltration* (`byte_rate + pkt_size_mean` $+5\text{k}/100 \to +250\text{k}/600$): confidence shifted $+0.80$ ($0.00 \to 0.80$, validated $\text{INCREASING}$).
  - **Evidence Scope Discrimination:** All explanations explicitly separate `CURRENT EVIDENCE` (feature is already elevated), `FORECAST EVIDENCE` (model projects forward trajectory), and `BOTH` (current elevation reinforced by forward momentum).
  - **Safety & Epistemic Humility:** Unavailable topology features (`fan_out`, internal ratios) are strictly masked; ground-truth labels and attack fraction are excluded; descriptions explicitly state model contributions rather than global causal claims.
  - **Consistency & Idempotence:** Deterministic idempotence test achieved 100% bitwise matching; 2% noise drift test confirmed bounded explanation coherence ($\Delta \text{conf} < 0.05$).
## Step 2B Experiment: future_security_risk_v1 (Future Security-Risk Score R(t+h) Validation)

- **Date**: 2026-08-29
- **Experiment Directory**: `artifacts/experiments/future_security_risk_v1/`
- **Objective**: Empirically evaluate and validate the bounded future security-risk score $R(t+h)$ for $h \in \{0, 1, 2, 3\}$ across 6 controlled security fixtures, forecast contradiction scenarios, horizon uncertainty decay, and the four held-out observed infiltration blocks.
- **Mathematical Formulation**:
  $$R(t+h) = \text{clip}\left( \text{Severity}(t+h) \times \text{Confidence}_{\text{stage}}(t+h) \times \text{Trust}(t+h) \times (1 - \text{Uncertainty}(t+h)) \times 1.50, \, 0.0, \, 1.0 \right)$$
- **Semantics**: Relative security-risk intensity of the predicted behavioural trajectory under current evidence and model trust. Explicitly NOT a calibrated attack probability.
- **Key Findings**:
  - **Controlled Fixtures**: Benign baseline evaluates to low risk ($R_0=0.1463 \to R_3=0.0622$, Unknown stage); Port Exploration evaluates to elevated Reconnaissance risk ($R_0=0.3443 \to R_1=0.3060$); Connection Flooding evaluates to high Impact risk ($R_0=0.6828 \to R_1=0.6069$); Outbound Surge evaluates to high Exfiltration risk ($R_0=0.5967 \to R_1=0.5304$).
  - **Forecast Contradiction Dampening**: Under a contradictory forecast (predicting sharp collapse of port exploration), $R(t+1)$ drops from $0.3468$ (reinforcing) to $0.0328$ (suppressed by $-0.31$) due to model trust degradation and counter-evidence integration.
  - **Horizon Decay Dynamics**: Open-loop risk natural moderates as prediction uncertainty rises ($U_0=0.10 \to U_1=0.20 \to U_2=0.35 \to U_3=0.50$) and forecast trust decays ($T_0=0.85 \to T_3=0.61$), preventing false confidence in distant projections.
  - **Held-Out Infiltration Blocks**: Descriptively evaluated across all 4 observed infiltration blocks (Block 1: mean $R_0=0.3256$, Block 2: $0.3368$, Block 3: $0.2909$, Block 4: $0.2904$). Max risk reached $0.6828$ during active flood/scan surges.
  - **Zero Label Leakage & Safety Invariants**: Verified $0$ label/attack_fraction inputs; unavailable topology features are suppressed; high risk with low trust cannot escalate to CRITICAL priority.
- **Gate Recommendation**: **GREEN** (Defensible, bounded future security-risk index satisfies PS concept of future window risk without making uncalibrated probability claims).



