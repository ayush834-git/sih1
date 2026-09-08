# PS 26153 AUTHORITATIVE EVIDENCE INDEX
## Predictive Cyber Defense / AI-Based Network Attack Forecasting
**Problem Statement:** SIH 26153 | **Organization:** National Technical Research Organisation (NTRO)  
**Standard:** Strict Code → Test → Artifact → Evidence Chain (`CLAIM <= EVIDENCE`)

This document is the single authoritative reference mapping every requirement of SIH PS 26153 directly to its executable implementation, automated test command, output artifact, quantitative metric, presentation-safe claim, and explicit limitation.

---

### Requirement 1: Live Network Packet Capture
- **PS Requirement**: Real-time packet acquisition directly from network interfaces to enable forward prediction from live traffic.
- **Implementation File(s)**:
  - [`runtime/live/backend.py`](file:///c:/Users/ayush/sih1/runtime/live/backend.py) (Npcap service and TShark binary discovery)
  - [`runtime/live/packet_capture.py`](file:///c:/Users/ayush/sih1/runtime/live/packet_capture.py) (`LivePacketCapture` engine with BPF filtering)
  - [`runtime/live/packet_parser.py`](file:///c:/Users/ayush/sih1/runtime/live/packet_parser.py) (`parse_tshark_line` zero-copy line parsing)
- **Test Command**:
  ```bash
  python -m pytest tests/test_live_capture.py -v
  ```
- **Artifact**:
  - [`artifacts/experiments/live_network_experiment_v1/manifest.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/live_network_experiment_v1/manifest.json)
  - [`artifacts/scratch/test_pipeline.pcap`](file:///c:/Users/ayush/sih1/artifacts/scratch/test_pipeline.pcap)
- **Exact Metric / Output**:
  - 20/20 live capture unit and integration tests pass.
  - Native capture demonstrated on Windows `\Device\NPF_Loopback` via Npcap 1.88 and TShark 4.6.8.
  - Generates SHA-256 hash per packet and composite `provenance_hash` per 10-second `NetworkState`.
  - Zero zombie or orphan TShark processes; subprocess PID tracking and graceful termination verified.
- **Safe Claim**:
  "Natively captures live network packets on Windows via Npcap and TShark, aggregating them into causal 10-second network states without precomputed replay files."
- **Limitation**:
  Verified in a controlled localhost loopback environment with port isolation; not yet deployed or validated on production high-throughput physical enterprise gateway taps.

---

### Requirement 2: Offline CSV Ingestion (CICFlowMeter)
- **PS Requirement**: Ability to ingest offline flow-level datasets (such as CSE-CIC-IDS2018) for offline training and evaluation.
- **Implementation File(s)**:
  - [`ingest/cic_flow.py`](file:///c:/Users/ayush/sih1/ingest/cic_flow.py) (`read_flows`, `build_states` CSV parser)
  - [`eval/dataset.py`](file:///c:/Users/ayush/sih1/eval/dataset.py) (`extract_transitions` contiguous sequence builder)
- **Test Command**:
  ```bash
  python -m pytest tests/test_ps_benchmarks.py::test_end_to_end_csv_to_ar5_inference -v
  ```
- **Artifact**:
  - [`artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.manifest.json`](file:///c:/Users/ayush/sih1/artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.manifest.json)
- **Exact Metric / Output**:
  - 8,640 states parsed from 851,108 flows (Wednesday-28 and Thursday-01).
  - 33 repeated CSV headers stripped; day-first timestamp parsing (`%d/%m/%Y %H:%M:%S`).
  - Label column strictly discarded during state construction to guarantee zero supervised leakage into network states.
- **Safe Claim**:
  "Ingests raw CSE-CIC-IDS2018 flow CSVs into standardized 10-second states, handling malformed lines and repeated headers without fabricating missing data."
- **Limitation**:
  NetFlow/CICFlowMeter CSVs omit raw packet payload bytes, fragmentation flags, and fine-grained host topology identifiers.

---

### Requirement 3: Offline PCAP / PCAPNG Ingestion
- **PS Requirement**: Parsing offline packet capture files (`.pcap` / `.pcapng`) into structured telemetry for retrospective analysis.
- **Implementation File(s)**:
  - [`ingest/pcap_ingest.py`](file:///c:/Users/ayush/sih1/ingest/pcap_ingest.py) (`read_packets_from_pcap`, `ingest_pcap_to_states`)
- **Test Command**:
  ```bash
  python -m pytest tests/test_ps_benchmarks.py::test_end_to_end_pcap_to_ar5_inference -v
  ```
- **Artifact**:
  - [`artifacts/scratch/test_pipeline.pcap`](file:///c:/Users/ayush/sih1/artifacts/scratch/test_pipeline.pcap)
- **Exact Metric / Output**:
  - TShark `-r` pipeline parses offline capture files into typed `ParsedPacket` streams and causal 10-second `NetworkState` sequences (`source=Source.PCAP`).
  - Successfully verified end-to-end against authoritative AR(5) model streaming inference.
- **Safe Claim**:
  "Supports offline PCAP/PCAPNG capture file ingestion using TShark field extraction and 10-second causal state aggregation."
- **Limitation**:
  Requires a local TShark installation for offline PCAP disassembly.

---

### Requirement 4: Flow-Level Feature Coverage
- **PS Requirement**: Extraction of bidirectional flow statistics including packet/byte counts, ratios, duration, IAT distributions, and TCP flags.
- **Implementation File(s)**:
  - [`runtime/live/flow_accumulator.py`](file:///c:/Users/ayush/sih1/runtime/live/flow_accumulator.py) (`FlowRecord`, `FlowAccumulator`)
  - [`runtime/live/packet_parser.py`](file:///c:/Users/ayush/sih1/runtime/live/packet_parser.py)
- **Test Command**:
  ```bash
  python -m pytest tests/test_ps_benchmarks.py::test_flow_record_extended_features -v
  ```
- **Artifact**:
  - [`runtime/live/flow_accumulator.py`](file:///c:/Users/ayush/sih1/runtime/live/flow_accumulator.py)
- **Exact Metric / Output**:
  - Computes bidirectional ratios: `fwd_bwd_packet_ratio`, `fwd_bwd_byte_ratio`, `fwd_packet_ratio`, `bwd_packet_ratio`, `fwd_byte_ratio`, `bwd_byte_ratio`.
  - Computes extended IAT: `mean_iat`, `std_iat`, `max_iat`, `var_iat`.
  - Tracks all 6 TCP flags: SYN, ACK, RST, FIN, PSH, URG counts.
  - Computes total bytes, total packets, and flow duration.
- **Safe Claim**:
  "Computes bidirectional flow metrics, IAT distributions, and complete TCP flag tallies adhering to standard flow-meter specifications."
- **Limitation**:
  Flow directionality (forward vs backward) is assigned based on the first observed packet within the tracking window.

---

### Requirement 5: Packet-Level Feature Coverage
- **PS Requirement**: Extraction of wire-level attributes including TTL, TTL variance, TCP window size, IP fragment flags, payload distribution, and retransmissions.
- **Implementation File(s)**:
  - [`runtime/live/packet_parser.py`](file:///c:/Users/ayush/sih1/runtime/live/packet_parser.py) (`ParsedPacket`, `parse_tshark_line`)
  - [`runtime/live/state_builder.py`](file:///c:/Users/ayush/sih1/runtime/live/state_builder.py) (`build_network_state_from_packets`)
  - [`core/contracts.py`](file:///c:/Users/ayush/sih1/core/contracts.py) (`NetworkState`)
- **Test Command**:
  ```bash
  python -m pytest tests/test_ps_benchmarks.py::test_packet_parser_extended_fields tests/test_ps_benchmarks.py::test_state_builder_packet_attributes -v
  ```
- **Artifact**:
  - [`runtime/live/state_builder.py`](file:///c:/Users/ayush/sih1/runtime/live/state_builder.py)
- **Exact Metric / Output**:
  - Extracts IP TTL mean and variance across packets in the window.
  - Extracts mean TCP window size (`tcp.window_size`).
  - Detects IP fragmentation via `ip.flags.mf` and `ip.frag_offset` (`fragment_count`).
  - Detects TCP retransmissions via `tcp.analysis.retransmission` (`retransmit_count`).
  - Computes payload size distributions (`payload_size_mean`, `pkt_size_mean`, `pkt_size_std`).
- **Safe Claim**:
  "Extracts wire-level packet attributes (TTL variance, TCP window, fragmentation flags, retransmissions) to detect low-level evasion techniques."
- **Limitation**:
  Wire-level fields are populated during live capture and offline PCAP ingestion; in legacy NetFlow CSVs, they are marked `FeatureAvailability.UNAVAILABLE` to maintain schema compatibility without fabrication.

---

### Requirement 6: Evolving Network-State Representation
- **PS Requirement**: Continuous discretization of raw telemetry into structured, evolving network-state representations.
- **Implementation File(s)**:
  - [`core/contracts.py`](file:///c:/Users/ayush/sih1/core/contracts.py) (`NetworkState` dataclass)
  - [`eval/dataset.py`](file:///c:/Users/ayush/sih1/eval/dataset.py) (`TransitionSample`)
  - [`runtime/live/state_builder.py`](file:///c:/Users/ayush/sih1/runtime/live/state_builder.py)
- **Test Command**:
  ```bash
  python -m pytest tests/test_temporal_representations.py tests/test_state_store.py -v
  ```
- **Artifact**:
  - [`artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.manifest.json`](file:///c:/Users/ayush/sih1/artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.manifest.json)
- **Exact Metric / Output**:
  - 10-second non-overlapping causal windows.
  - 21 schema features (15 active CSV features, 6 wire-packet extensions).
  - Explicit session boundary and gap tracking (`gap_before`, `gap_after`, `session_id`). Transitions are strictly forbidden across session gaps.
- **Safe Claim**:
  "Constructs discrete, causal 10-second network states with zero future leakage, explicitly flagging idle gaps without fabricating transitions."
- **Limitation**:
  10-second window quantization cannot resolve sub-second micro-bursts or single-packet timing transients.

---

### Requirement 7: Learned Temporal Dynamics Model
- **PS Requirement**: Moving beyond static classification by learning transition dynamics over state trajectories.
- **Implementation File(s)**:
  - [`eval/models_v2.py`](file:///c:/Users/ayush/sih1/eval/models_v2.py) (`ARStyleBaselineV2`)
  - [`eval/rollout.py`](file:///c:/Users/ayush/sih1/eval/rollout.py) (`MultiStepRolloutEngine`)
  - [`artifacts/models/ar5_authoritative/`](file:///c:/Users/ayush/sih1/artifacts/models/ar5_authoritative/)
- **Test Command**:
  ```bash
  python -m pytest tests/test_day4.py tests/test_statistical_hardening.py -v
  ```
- **Artifact**:
  - [`artifacts/models/ar5_authoritative/model_coefficients.json`](file:///c:/Users/ayush/sih1/artifacts/models/ar5_authoritative/model_coefficients.json)
  - [`artifacts/experiments/delta_baseline_v2/results_summary.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_baseline_v2/results_summary.json)
- **Exact Metric / Output**:
  - Evaluated on 6,727 transitions ($p=5$, 60/15/25 split).
  - AR(5) achieves **68.10% Directional Accuracy** on held-out test split, outperforming Persistence (32.89%) and Zero-Change (50.0%).
  - Median Normalized MAE = 0.4052.
- **Safe Claim**:
  "Employs an interpretable autoregressive temporal world-model formulation for discrete network states, achieving 68.10% test directional accuracy."
- **Limitation**:
  Operates as an autoregressive linear dynamics model over delta states ($\Delta S \in \mathbb{R}^{15}$); it is NOT a deep generative world model (LSTM/Transformer/GNN).

---

### Requirement 8: Multi-Step Attack Forecasting
- **PS Requirement**: Forecasting upcoming network states multiple observation windows into the future.
- **Implementation File(s)**:
  - [`eval/rollout.py`](file:///c:/Users/ayush/sih1/eval/rollout.py) (`MultiStepRolloutEngine`)
  - [`scenarios/demo/engine.py`](file:///c:/Users/ayush/sih1/scenarios/demo/engine.py)
  - [`eval/run_lead_time_experiment.py`](file:///c:/Users/ayush/sih1/eval/run_lead_time_experiment.py) (Task 16 empirical lead-time harness)
- **Test Command**:
  ```bash
  python -m pytest tests/test_demo_adapter.py tests/test_day5.py tests/test_lead_time_experiment.py -v
  ```
- **Artifact**:
  - [`artifacts/experiments/delta_rollout_uncertainty_v1_corrected/results_summary.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_rollout_uncertainty_v1_corrected/results_summary.json)
  - [`artifacts/experiments/lead_time_v1/`](file:///c:/Users/ayush/sih1/artifacts/experiments/lead_time_v1/) (`run_manifest.json`, `lead_time_results.json`, `comparison.csv`, `methodology.md`)
  - [`docs/LEAD_TIME_METHODOLOGY.md`](file:///c:/Users/ayush/sih1/docs/LEAD_TIME_METHODOLOGY.md)
- **Exact Metric / Output**:
  - Recursive open-loop rollout for $h=1$ (10s, DA=68.09%), $h=2$ (20s, DA=50.95%), $h=3$ (30s, DA=50.21%).
  - Empirical residual bootstrap ($B=100$) provides verified prediction interval coverage (80% nominal -> 81.9% empirical; 90% nominal -> 89.7% empirical; 95% nominal -> 93.9% empirical).
  - Receding-horizon updates maintain DA $\approx 68.10\%$ by conditioning each step on newly observed states.
  - Empirical Lead Time: AR(5) produces an earlier alert signal (+10.0s advance warning) across live Npcap captures and dataset onsets, demonstrating a trade-off between early recall and false-alarm sensitivity.
  - Actionable Sensitivity Analysis: Tested across modeled action durations ($T_{\text{action}} \in \{5\text{s}, 10\text{s}, 20\text{s}, 30\text{s}\}$), demonstrating how defensive readiness governs operational utility.
- **Safe Claim**:
  "Forecasts evolving network states 10 to 30 seconds ahead using recursive multi-step rollout with empirical bootstrap confidence bounds, providing earlier warning signals under documented operational trade-offs."
- **Limitation**:
  A 10-second prediction horizon does not equate to 10 seconds of operational SOC reaction time (`modeled_action_duration_s = 20` is a modeled experimental assumption). Open-loop forecast accuracy decays toward chance beyond 20–30 seconds without receding-horizon telemetry updates.

---

### Requirement 9: Attack Timeline & MITRE ATT&CK Mapping
- **PS Requirement**: Grounding forecasted dynamics in supervised attack timelines and recognized cybersecurity frameworks.
- **Implementation File(s)**:
  - [`eval/labels.py`](file:///c:/Users/ayush/sih1/eval/labels.py) (`AttackInterval`, `MITRE_ATTACK_TAXONOMY`, `annotate_transitions`)
  - [`security/bridge.py`](file:///c:/Users/ayush/sih1/security/bridge.py) (`BehavioralSecurityBridge`)
  - [`security/contracts.py`](file:///c:/Users/ayush/sih1/security/contracts.py)
- **Test Command**:
  ```bash
  python -m pytest tests/test_ps_benchmarks.py::test_supervised_labels_annotation -v
  ```
- **Artifact**:
  - [`eval/labels.py`](file:///c:/Users/ayush/sih1/eval/labels.py)
- **Exact Metric / Output**:
  - Formally maps attack progression to 5 MITRE ATT&CK stages:
    - Reconnaissance: T1595 (Active Scanning) [Tactic: TA0043]
    - Infiltration: T1190 (Exploit Public-Facing Application) [Tactic: TA0001]
    - Lateral Movement: T1021 (Remote Services) [Tactic: TA0008]
    - Exfiltration: T1048 (Exfiltration Over Alternative Protocol) [Tactic: TA0010]
    - Impact: T1499 (Endpoint DoS) [Tactic: TA0040]
- **Safe Claim**:
  "Maps forecasted behavioral vectors to MITRE ATT&CK stages through transparent, causal rule-based security hypotheses."
- **Limitation**:
  Stage boundaries in benchmark datasets are derived from published scenario execution documentation rather than per-packet host-level attacker audit logs.

---

### Requirement 10: Calibrated Attack Progression Probability
- **PS Requirement**: Computing calibrated empirical probability of attack progression across upcoming observation windows.
- **Implementation File(s)**:
  - [`eval/progression_probability.py`](file:///c:/Users/ayush/sih1/eval/progression_probability.py) (`ProgressionProbabilityModel`)
  - [`eval/run_logistic_benchmark.py`](file:///c:/Users/ayush/sih1/eval/run_logistic_benchmark.py)
- **Test Command**:
  ```bash
  python -m pytest tests/test_ps_benchmarks.py::test_progression_probability_calibration -v
  ```
- **Artifact**:
  - [`artifacts/experiments/logistic_regression_benchmark_v1/benchmark_results.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/logistic_regression_benchmark_v1/benchmark_results.json)
- **Exact Metric / Output**:
  - Evaluated on held-out test split ($N=1,682$, 345 attack windows, 1,337 benign windows):
    - **Brier Score**: `0.1278`
    - **Expected Calibration Error (ECE)**: `0.0890` (10 equal-width bins)
    - **Maximum Calibration Error (MCE)**: `0.3379`
    - **ROC-AUC**: `0.8143`
    - **Precision**: `86.44%` (51 TP, 8 FP)
    - **False Positive Rate (FPR)**: `0.0060` (0.60%)
    - **Recall**: `14.78%`
  - Fitted strictly on train/val via `PredefinedSplit`; test data was strictly unobserved during calibration.
- **Safe Claim**:
  "Emits calibrated empirical attack progression probabilities (Brier = 0.1278, ECE = 0.0890, Precision = 86.4%, FPR = 0.60%) distinct from heuristic risk indices."
- **Limitation**:
  High precision (86.4%) and low false alarm rate (0.60%) come at the cost of detection recall (14.78%) at the default operating threshold.

---

### Requirement 11: Heuristic Future Security Risk Scoring
- **PS Requirement**: Synthesizing projected state trajectories into an actionable future risk index.
- **Implementation File(s)**:
  - [`security/risk_engine.py`](file:///c:/Users/ayush/sih1/security/risk_engine.py) (`SecurityRiskEngine`)
  - [`security/bridge_v3.py`](file:///c:/Users/ayush/sih1/security/bridge_v3.py)
- **Test Command**:
  ```bash
  python -m pytest tests/test_future_security_risk_validation.py -v
  ```
- **Artifact**:
  - [`artifacts/experiments/future_security_risk_validation_v1/results_summary.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/future_security_risk_validation_v1/results_summary.json)
- **Exact Metric / Output**:
  - Produces bounded heuristic risk score $R(t+h) \in [0, 1]$ across horizons $h \in \{1, 2, 3\}$.
  - Dynamically dampens risk score upon observation contradiction ($R(t+h)$ suppresses from 0.78 to 0.22 when probe abruptly ceases).
- **Safe Claim**:
  "Computes multi-horizon Future Security Risk $R(t+h) \in [0, 1]$ balancing projected threat velocity and observation trust."
- **Limitation**:
  Future Security Risk $R(t+h)$ is an operational composite prioritization index, NOT an attack probability or frequentist likelihood.

---

### Requirement 12: Static Baseline Benchmark (Logistic Regression)
- **PS Requirement**: Rigorous comparative benchmarking against standard baseline detectors, specifically static Logistic Regression.
- **Implementation File(s)**:
  - [`eval/run_logistic_benchmark.py`](file:///c:/Users/ayush/sih1/eval/run_logistic_benchmark.py)
  - [`eval/baseline_detectors.py`](file:///c:/Users/ayush/sih1/eval/baseline_detectors.py)
- **Test Command**:
  ```bash
  python -m pytest tests/test_ps_benchmarks.py::test_benchmark_artifacts_exist -v
  ```
- **Artifact**:
  - [`artifacts/experiments/logistic_regression_benchmark_v1/benchmark_comparison.csv`](file:///c:/Users/ayush/sih1/artifacts/experiments/logistic_regression_benchmark_v1/benchmark_comparison.csv)
- **Exact Metric / Output**:
  - Evaluated on identical 6,727 transitions (1,682 test samples, 15 features, 60/15/25 split):
    - **Static Logistic Regression**: F1 = `0.4000`, Precision = `0.3069`, Recall = `0.5743`, FPR = `0.3323` (33.2%), Accuracy = `0.6486`.
    - **Temporal AR(5) Predictive Trajectory**: F1 = `0.3575`, Precision = `0.2319`, Recall = **`0.7797`** (+20.5% higher recall), FPR = `0.6664`, Accuracy = `0.4251`.
    - **Calibrated Progression Probability**: F1 = `0.2525`, Precision = **`0.8644`** (+55.7% higher precision), Recall = `0.1478`, FPR = **`0.0060`** (0.60%), Accuracy = **`0.8205`**.
- **Safe Claim**:
  "Demonstrates measurable trade-offs against static Logistic Regression: AR(5) trajectory forecasting achieves +20.5% higher recall by projecting threat momentum, while calibrated progression probability delivers high precision (86.4%) and low false alarm rates (0.60%)."
- **Limitation**:
  There is no universal superiority: AR(5) incurs a higher false positive rate (66.6%) at default operating thresholds, whereas the calibrated model trades off recall (14.8%) to achieve low false alarms (0.60%).

---

### Requirement 13: Generalization Beyond Memorization (Within-Family)
- **PS Requirement**: Verifying that the model learns underlying transition dynamics rather than memorizing session timestamps or tokens.
- **Implementation File(s)**:
  - [`eval/dataset.py`](file:///c:/Users/ayush/sih1/eval/dataset.py)
  - [`eval/models_v2.py`](file:///c:/Users/ayush/sih1/eval/models_v2.py)
- **Test Command**:
  ```bash
  python -m pytest tests/test_statistical_hardening.py -v
  ```
- **Artifact**:
  - [`artifacts/experiments/delta_baseline_v2/results_summary.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/delta_baseline_v2/results_summary.json)
  - [`artifacts/experiments/statistical_hardening_v1/`](file:///c:/Users/ayush/sih1/artifacts/experiments/statistical_hardening_v1/)
- **Exact Metric / Output**:
  - Leave-One-Block-Out evaluation across 4 held-out infiltration blocks shows consistent directional accuracy gains (+0.95% to +2.82% over AR(3)).
  - Thursday test split achieves 68.10% Directional Accuracy with zero training timestamp overlap.
- **Safe Claim**:
  "Maintains consistent directional accuracy across 4 held-out infiltration blocks without memorizing session timestamps."
- **Limitation**:
  All 4 infiltration blocks originate from the same victim enterprise topology (CSE-CIC-IDS2018 testbed).

---

### Requirement 14: Generalization to Unseen Attack Family (DDoS)
- **PS Requirement**: Evaluating model transfer to an entirely novel attack family unseen during training.
- **Implementation File(s)**:
  - [`eval/run_unseen_attack_experiment.py`](file:///c:/Users/ayush/sih1/eval/run_unseen_attack_experiment.py)
- **Test Command**:
  ```bash
  python -m pytest tests/test_ps_benchmarks.py::test_unseen_attack_artifacts_exist -v
  ```
- **Artifact**:
  - [`artifacts/experiments/unseen_attack_generalization_v1/generalization_results.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/unseen_attack_generalization_v1/generalization_results.json)
- **Exact Metric / Output**:
  - Evaluated on Wednesday-21 Volumetric DDoS-HOIC ($N=40$ transitions, 60 states):
    - Overall Directional Accuracy: `53.83%` (baseline chance = 50.0%)
    - Non-Zero Directional Accuracy: `64.60%` (when feature changes direction)
    - Normalized MAE: `1.88` (nearly 2x training interquartile range)
- **Safe Claim**:
  "We observed limited cross-family directional transfer on an unseen DDoS-HOIC evaluation slice (N=40), while magnitude calibration degraded under the observed distribution shift. This is preliminary evidence of transfer, not proof of broad unseen-attack generalization."
- **Limitation**:
  Evaluated on 40 contiguous attack transitions. Volumetric scaling shifted by two orders of magnitude, demonstrating that directional momentum transfers but magnitude scales fail without adaptive re-calibration. Marked `PARTIALLY COVERED`.


---

### Requirement 15: Explainability & Feature Attribution
- **PS Requirement**: Providing interpretable, auditable reasoning connecting raw telemetry features to forecasts and security assessments.
- **Implementation File(s)**:
  - [`explainability/engine.py`](file:///c:/Users/ayush/sih1/explainability/engine.py) (`ExplainabilityEngine`)
  - [`explainability/contracts.py`](file:///c:/Users/ayush/sih1/explainability/contracts.py)
- **Test Command**:
  ```bash
  python -m pytest tests/test_explainability.py tests/test_demo_adapter.py -v
  ```
- **Artifact**:
  - [`artifacts/experiments/explainability_v1/results_summary.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/explainability_v1/results_summary.json)
- **Exact Metric / Output**:
  - Exact mathematical lag decomposition for every predicted feature:
    $$\Delta \hat{x}_j(t+1) = c_j + \sum_{l=1}^p \beta_{j,l} \cdot \Delta x_j(t - l + 1)$$
  - Emits normalized feature contributions, signed momentum directions, explicit supporting evidence, and counter-evidence.
- **Safe Claim**:
  "Exposes complete causal reasoning for every forecast, showing exact lag coefficients, momentum features, and counter-evidence without hardcoded text templates."
- **Limitation**:
  Attribution relies on linear autoregressive coefficient weighting rather than cooperative game-theoretic Shapley values.

---

### Requirement 16: Enterprise / Critical Infrastructure Applicability
- **PS Requirement**: Actionable decision support tailored for enterprise and critical information infrastructure operations.
- **Implementation File(s)**:
  - [`core/priority/engine.py`](file:///c:/Users/ayush/sih1/core/priority/engine.py) (`PriorityEngine`)
  - [`core/response/recommendations.py`](file:///c:/Users/ayush/sih1/core/response/recommendations.py) (`ResponseRecommendationEngine`)
  - [`core/response/routing.py`](file:///c:/Users/ayush/sih1/core/response/routing.py) (`RoleRelevanceEngine`)
- **Test Command**:
  ```bash
  python -m pytest tests/test_api.py -v
  npm test --prefix ui
  ```
- **Artifact**:
  - [`ui/src/pages/AlertsQueuePage.tsx`](file:///c:/Users/ayush/sih1/ui/src/pages/AlertsQueuePage.tsx)
  - [`ui/src/test/runtime.test.mjs`](file:///c:/Users/ayush/sih1/ui/src/test/runtime.test.mjs)
- **Exact Metric / Output**:
  - 4 specialized operational roles: SOC Analyst, Network Defender, Incident Commander, Data Protection Officer.
  - Policy enforcement gate: Actions with operational blast radius (`BLOCK_PORT`, `QUARANTINE_IP`) strictly require human approval (`requires_human = True`).
  - Reversible response primitives: `RATE_LIMIT_PORT`, `TEMPORARY_ISOLATE` with rollback mechanisms.
- **Safe Claim**:
  "Architected for enterprise/CII decision-support with human-in-the-loop policy gates and reversible containment primitives, verified in controlled environments."
- **Limitation**:
  Evaluated in controlled simulation, synthetic scenario replays, and localhost loopback; not yet deployed in live physical critical infrastructure or NCIIPC production settings. Marked `PARTIALLY COVERED`.

---

### Requirement 17: Dynamic Contradiction & Reconsideration
- **PS Requirement**: Continuous self-monitoring to detect when live observations contradict previous forecasts and de-escalate alarms.
- **Implementation File(s)**:
  - [`security/bridge_v3.py`](file:///c:/Users/ayush/sih1/security/bridge_v3.py)
  - [`ui/src/pages/OperationalSimulationPage.tsx`](file:///c:/Users/ayush/sih1/ui/src/pages/OperationalSimulationPage.tsx)
- **Test Command**:
  ```bash
  python -m pytest tests/test_future_security_risk_validation.py::test_07_contradiction_sequence_and_suppression -v
  npm test --prefix ui
  ```
- **Artifact**:
  - [`artifacts/experiments/future_security_risk_validation_v1/results_summary.json`](file:///c:/Users/ayush/sih1/artifacts/experiments/future_security_risk_validation_v1/results_summary.json)
- **Exact Metric / Output**:
  - Telemetry contradicting previous forecast immediately triggers trust degradation (composite trust drops from 0.85 to 0.40).
  - Priority de-escalates (`MEDIUM` -> `INFO`); UI displays yellow contradiction reconsideration banner, preventing alert fatigue.
- **Safe Claim**:
  "Dynamically detects when live observations contradict previous forecasts, immediately lowering trust and de-escalating containment actions."
- **Limitation**:
  Contradiction sensitivity thresholds are calibrated against training empirical distribution bounds.

---

### Requirement 18: Reproducibility & Open-Source Artifacts
- **PS Requirement**: Complete, auditable, and reproducible research artifacts and codebase.
- **Implementation File(s)**:
  - [`config/default.json`](file:///c:/Users/ayush/sih1/config/default.json)
  - [`eval/run_logistic_benchmark.py`](file:///c:/Users/ayush/sih1/eval/run_logistic_benchmark.py)
  - [`eval/run_unseen_attack_experiment.py`](file:///c:/Users/ayush/sih1/eval/run_unseen_attack_experiment.py)
  - [`scripts/run_live_experiment.py`](file:///c:/Users/ayush/sih1/scripts/run_live_experiment.py)
- **Test Command**:
  ```bash
  python -m pytest tests/ -q
  npm test --prefix ui
  ```
- **Artifact**:
  - [`artifacts/models/ar5_authoritative/`](file:///c:/Users/ayush/sih1/artifacts/models/ar5_authoritative/)
  - [`artifacts/experiments/`](file:///c:/Users/ayush/sih1/artifacts/experiments/)
- **Exact Metric / Output**:
  - 268 backend pytest tests pass (0 failures, 0 regressions).
  - 21 frontend Node.js test runner tests pass across 7 suites.
  - Model weights, normalization scales, and experiment configurations fully serialized with SHA-256 integrity hashes.
- **Safe Claim**:
  "Fully reproducible open-source framework with serialized model coefficients, audited experiment manifests, and deterministic test suites."
- **Limitation**:
  Multi-gigabyte raw dataset CSVs (CSE-CIC-IDS2018) require external download from the official University of New Brunswick repository due to Git repository size limitations.

---

## Overall Audit Verdict

> **“The implementation and evaluation are technically defensible against expert scrutiny, subject to the documented limitations and partial coverage of unseen-family generalization and enterprise/CII validation.”**

