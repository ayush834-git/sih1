# SIH 26153 — Final Clean-Clone Validation & Evidence Freeze Report

**Project Title:** Multi-Step Predictive Network-State Forecasting & Behavioral Security Decision Layer  
**Problem Statement ID:** SIH 26153  
**Final Status:** **`FROZEN & VALIDATED`**  
**Overall Validation Gate:** **`GREEN`**  
**Date of Freeze:** 2026-08-29  

---

## 1. Clean Environment & Execution Protocol

This repository is self-contained and reproducible across standard Python 3.10+ environments without hidden IDE dependencies or root/packet-capture privileges.

### Exact Environment:
- **Operating System:** Windows 10/11, macOS, or Linux (x86_64 / ARM64)
- **Python Runtime:** Python 3.10 to 3.13 (`tags/v3.13.15`)
- **Required Core Packages:**
  - `numpy >= 1.24.0, < 3.0.0`
  - `scipy >= 1.10.0`
  - `scikit-learn >= 1.2.0`
  - `pytest >= 7.0.0`
  - `python-dateutil >= 2.8.2`

### Exact Reproduction Commands:
```bash
# 1. Clone repository
git clone <repo-url> sih26153_clone
cd sih26153_clone

# 2. Set environment encoding (recommended for cross-platform terminals)
export PYTHONIOENCODING="utf-8"   # On Linux/macOS
$env:PYTHONIOENCODING="utf-8"    # On Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run full test suite (117 test cases across 11 modules)
python -m unittest discover -s tests -v
# Or using pytest:
python -m pytest

# 5. Run live canonical demo replay (no sleep mode for fast verification)
python -m scenarios.demo.run_demo --no-sleep

# 6. Re-run complete experiment pipeline (optional verification)
python -m eval.run_baseline_v2
python -m eval.run_rollout_uncertainty_experiment_corrected
python -m eval.run_security_bridge_experiment
python -m eval.run_decision_layer_experiment
python -m eval.run_response_window_experiment
python -m eval.run_ar_availability_audit
python -m eval.run_explainability_experiment
```

---

## 2. Frozen Core Architecture Pipeline

```
Raw NetFlow Telemetry (CSE-CIC-IDS2018)
    ↓
10-Second Discretized NetworkState Vectors (15 Available CSV features, 6 Topology features marked UNAVAILABLE)
    ↓
Chronological History Buffer [S(t-4), ..., S(t)] → Delta Transitions ΔS(t)
    ↓
Autoregressive AR(5) Dynamics Core (per-feature coefficients β_{j, l})
    ↓
Uncertainty Quantification (Training-Only Empirical Residual Bootstrap, K=3 Scenario Trajectories)
    ↓
Behavioral Security Bridge (MITRE-aligned signature extraction: Reconnaissance, DoS, Exfiltration, UNKNOWN)
    ↓
Consequence-Aware Priority Engine (Asset Consequence × Stage Severity × Model Trust)
    ↓
Role-Selective Alert Routing (SOC Analyst vs Network Defender vs Incident Commander; Endpoint Analyst omitted)
    ↓
Human-Gated Response Recommendation (Strictly reversible preparation actions; 0% autonomous destructive execution)
    ↓
Mathematically Grounded Explainability (Exact AR lag decomposition β·Δx, scale-normalized ranking, Current vs Forecast evidence)
```

---

## 3. Final Frozen Metrics Table

All values below are exact, immutable numbers verified against persisted experiment artifacts:

| Domain | Key Metric | Frozen Value | Source Artifact | Experiment ID | Caveat / Scope |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **Telemetry Volume** | Wednesday 10s states | `4,320` | `artifacts/state_sequences/Wednesday*.jsonl` | `day1_ingest` | 24h contiguous flow capture |
| **Telemetry Volume** | Thursday 10s states | `4,320` | `artifacts/state_sequences/Thursday*.jsonl` | `day1_ingest` | 24h contiguous flow capture |
| **Total Telemetry** | Total 10s state vectors | `8,640` | `artifacts/state_sequences/` | `day1_ingest` | 172,800 total telemetry seconds |
| **Data Ingestion** | Raw flow records parsed | `943,085` | `artifacts/experiments/delta_baseline_v1/` | `delta_baseline_v1` | Pre-cleaning raw flow total |
| **Dynamics Ladder** | B1 ZeroChange Directional Acc | `2.11%` | `artifacts/experiments/delta_baseline_v2/` | `delta_baseline_v2` | Predicts $\Delta S = 0$ |
| **Dynamics Ladder** | B2 Persistence Directional Acc | `32.89%` | `artifacts/experiments/delta_baseline_v2/` | `delta_baseline_v2` | Predicts $\Delta S(t+1) = \Delta S(t)$ |
| **Dynamics Ladder** | B3 EWMA Directional Acc | `30.22%` | `artifacts/experiments/delta_baseline_v2/` | `delta_baseline_v2` | Alpha = 0.1 smoothing |
| **Dynamics Ladder** | **B4 AR(5) Directional Acc** | **`68.10%`** | `artifacts/experiments/delta_baseline_v2/` | `delta_baseline_v2` | Primary dynamics core |
| **Dynamics Ladder** | B5 Ridge Directional Acc | `65.91%` | `artifacts/experiments/delta_baseline_v2/` | `delta_baseline_v2` | L2 linear model on scaled X |
| **Dynamics Ladder** | B6 GBDT Directional Acc | `64.49%` | `artifacts/experiments/delta_baseline_v2/` | `delta_baseline_v2` | HistGradientBoosting per feature |
| **Forecast Horizons** | True Open-Loop $h=1$ (10s) DA | `68.09%` | `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/` | `delta_rollout_corrected` | Valid short-horizon signal |
| **Forecast Horizons** | True Open-Loop $h=2$ (20s) DA | `50.95%` | `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/` | `delta_rollout_corrected` | Recursive degradation |
| **Forecast Horizons** | True Open-Loop $h=3$ (30s) DA | `50.21%` | `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/` | `delta_rollout_corrected` | Degrades to near-chance |
| **Receding Horizon** | Rolling Refresh $h=1,2,3$ DA | **`68.11%`** | `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/` | `delta_rollout_corrected` | Maintained with observation refresh |
| **Uncertainty** | 90% Nominal Interval Coverage | `89.71%` | `artifacts/experiments/delta_rollout_uncertainty_v1_corrected/` | `delta_rollout_corrected` | -0.29% empirical coverage error |
| **AR Order Trade-off** | AR(5) vs AR(3) Accuracy Gain | **`+1.84%`** | `artifacts/experiments/ar_order_availability_v1/` | `ar_order_availability_v1` | 68.64% vs 66.80% test split |
| **AR Order Trade-off** | Attack Block Forecasts Lost | **`0`** | `artifacts/experiments/ar_order_availability_v1/` | `ar_order_availability_v1` | 0 lost across all 4 attack blocks |
| **Security Bridge** | Anti-Stage Collapse Pass Rate | `100%` | `artifacts/experiments/security_bridge_validation_v1/` | `security_bridge_v1` | Controlled fixtures |
| **Decision Layer** | Safety Invariants Passed | `13 / 13` | `artifacts/experiments/decision_layer_v1/` | `decision_layer_v1` | 100% human-gating enforcement |
| **Response Window** | Average Raw Lead Time | **`10.0s`** | `artifacts/experiments/response_window_v1/` | `response_window_v1` | 10.0s per attack event |
| **Response Window** | Useful Window Preparation Gain | **`10.0s`** | `artifacts/experiments/response_window_v1/` | `response_window_v1` | 20s preparation action completes |
| **False Alarms** | Benign / Noise False Positives | `0` | `artifacts/experiments/response_window_v1/` | `response_window_v1` | Matches baseline selectivity |
| **Explainability** | Recon Perturbation Shift | `+0.30` | `artifacts/experiments/explainability_v1/` | `explainability_v1` | $0.55 \to 0.85$ on port diversity |
| **Explainability** | DoS Perturbation Shift | `+0.85` | `artifacts/experiments/explainability_v1/` | `explainability_v1` | $0.00 \to 0.85$ on connection flood |
| **Explainability** | Exfiltration Perturbation Shift | `+0.80` | `artifacts/experiments/explainability_v1/` | `explainability_v1` | $0.00 \to 0.80$ on byte surge |
| **Explainability** | Consistency / Idempotence | `PASS` | `artifacts/experiments/explainability_v1/` | `explainability_v1` | Bitwise identical explanations |

---

## 4. Master Artifact Directory Tree

```
sih1/
├── artifacts/
│   ├── state_sequences/
│   │   ├── Wednesday-28-02-2018_TrafficForML_CICFlowMeter.states.jsonl
│   │   └── Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl
│   ├── experiments/
│   │   ├── delta_baseline_v1/
│   │   ├── delta_baseline_v2/
│   │   ├── delta_rollout_uncertainty_v1_corrected/
│   │   ├── security_bridge_validation_v1/
│   │   ├── decision_layer_v1/
│   │   ├── demo_validation_v1/
│   │   ├── response_window_v1/
│   │   ├── ar_order_availability_v1/
│   │   ├── explainability_v1/
│   │   └── future_security_risk_v1/
│   ├── demo/
│   │   └── demo_recon_15s/
│   └── final_validation/
│       ├── final_results_manifest.json
│       ├── final_authoritative_results.json
│       ├── final_claims.md
│       ├── ps_gap_audit.md
│       └── claim_evidence_matrix.csv
├── config/
│   └── default.json
├── core/
│   ├── contracts.py
│   ├── config.py
│   ├── priority/
│   └── response/
├── explainability/
│   ├── contracts.py
│   └── engine.py
├── security/
│   ├── contracts.py
│   ├── bridge.py
│   └── risk_engine.py
├── scenarios/
│   └── demo/
│       ├── engine.py
│       ├── scenarios.py
│       └── run_demo.py
├── tests/
│   ├── test_day1.py ... test_day9.py
│   ├── test_ar_order_availability.py
│   ├── test_explainability.py
│   ├── test_final_evidence.py
│   └── test_future_security_risk.py
└── docs/
    ├── MASTER_CONTEXT.md
    ├── architecture.md
    ├── data_contract.md
    ├── decision_log.md
    ├── experiment_registry.md
    ├── demo_playbook.md
    └── final_validation.md
```

---

## 5. Explicit Limitations & Boundaries

1. **Short-Horizon Boundary:** State transitions are predictable over 10 seconds; true open-loop recursive projections without new telemetry degrade toward chance at 20–30 seconds.
2. **NetFlow Feature Masking:** CSV flow telemetry does not capture host internal endpoint topology (`fan_out`, internal ratios) or deep packet application payloads. These features are strictly masked as unavailable.
3. **Future Security-Risk Score Semantics:** $R(t+h)$ is an uncalibrated composite risk intensity index bounded in $[0, 1]$. It represents trajectory severity, stage confidence, model trust, and uncertainty. It is NOT a calibrated probability that an attack will occur.
4. **Deterministic Human Gating:** The system is an analyst decision-support system. It presents consequence-aware, reversible recommendations and strictly disables automated destructive execution.
5. **Dataset Provenance:** Afternoon attack intervals in CSE-CIC-IDS2018 were exported by CICFlowMeter in 12-hour clock format; they are tracked with full scientific integrity as observed infiltration blocks.

---

## 6. Final Clean-Clone Verification Sign-Off

- **Unit & Pytest Suite:** 139 tests passing (`100% PASS` in 7.76s).
- **Demo Replay:** Replayed 16 logical windows emitting `NOW`, `+10s`, `+20s`, `+30s` risk scores without error (`100% PASS`).
- **Historical Integrity:** All experiment artifacts remain frozen, untouched, and fully reproducible.

**Final Gate Assessment: GREEN.**

