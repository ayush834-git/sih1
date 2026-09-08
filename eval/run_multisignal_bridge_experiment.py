"""
Multi-Signal Causal Behavioral Normalization — A/B/C Research Experiment Runner.

SIH PS 26153: AI-Based Network Attack Forecasting from Network Traffic Data.

Strict Experimental Protocol:
- Compares THREE bridge variants:
  A. OLD_STATIC: BehavioralSecurityBridge
  B. PORT_DYNAMIC: RollingBaselineSecurityBridge (W=30, k=3.0)
  C. MULTI_SIGNAL: MultiSignalRollingBaselineSecurityBridge (W=30, k=3.0, 4 orthogonal signals)
- Performs 5-way signal ablation on the NEW bridge:
  1. PORT_ONLY (port diversity only)
  2. PORT_FLOW (port + flow-rate)
  3. PORT_TIMING (port + timing compression)
  4. PORT_BYTE (port + byte-rate)
  5. FULL_MULTISIGNAL (port + flow + byte + timing)
- Evaluates on identical populations:
  * Benign all test windows (N=1339)
  * Pre-onset benign context windows (N=584)
  * Block 4 infiltration attack (N=343)
  * All 4 infiltration blocks pooled (N=1708)
  * Per-block evaluation across Blocks 1, 2, 3, 4
- Preserves temporal autocorrelation using Moving Block Bootstrap (block=30 windows / 300s, 2000 resamples).
- Generates 8 publication-quality diagnostic plots and structured CSV/JSON artifacts.
"""
from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

from core.contracts import (
    Direction,
    NetworkState,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    new_id,
)
from eval.dataset import (
    CSV_AVAILABLE_FEATURES,
    OBSERVED_INFILTRATION_BLOCKS,
    load_states_from_jsonl,
)
from eval.rollout import MultiStepRolloutEngine
from eval.run_future_security_risk_validation import (
    compute_distribution_stats,
    evaluate_sequential_stream,
    moving_block_bootstrap_difference,
)
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.scenarios import get_demo_scenario_states
from security.bridge import BehavioralSecurityBridge
from security.bridge_v2 import RollingBaselineSecurityBridge
from security.bridge_v3 import MultiSignalRollingBaselineSecurityBridge
from security.contracts import SignatureType
from security.risk_engine import SecurityRiskEngine


OUT_DIR = Path("artifacts/experiments/bridge_multisignal_experiment_v1")
FIG_DIR = OUT_DIR / "figures"


def count_false_escalation_episodes(scores: Sequence[float], threshold: float = 0.50, min_len: int = 3) -> int:
    """Counts contiguous episodes where R >= threshold for >= min_len consecutive windows."""
    episodes = 0
    curr_len = 0
    for s in scores:
        if s >= threshold:
            curr_len += 1
        else:
            if curr_len >= min_len:
                episodes += 1
            curr_len = 0
    if curr_len >= min_len:
        episodes += 1
    return episodes


def evaluate_signature_rates(bridge: BehavioralSecurityBridge, states: Sequence[NetworkState]) -> dict[str, float]:
    """Computes active signature trigger rates for all signature types."""
    if hasattr(bridge, "reset"):
        bridge.reset()
    counts = {
        "recon": 0,
        "flood": 0,
        "exfil": 0,
        "timing": 0,
    }
    for st in states:
        sigs = bridge.extract_signatures(st)
        types = {s.signature_type for s in sigs}
        if SignatureType.RECONNAISSANCE_PORT_EXPLORATION in types:
            counts["recon"] += 1
        if SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE in types:
            counts["flood"] += 1
        if SignatureType.EXFILTRATION_OUTBOUND_SURGE in types:
            counts["exfil"] += 1
        if SignatureType.TIMING_BEHAVIOURAL_ANOMALY in types:
            counts["timing"] += 1

    n = max(1, len(states))
    return {k: round(v / n, 4) for k, v in counts.items()}


def run_multisignal_experiment(seed: int = 42) -> dict[str, Any]:
    print("=" * 80)
    print("SIH PS 26153: MULTI-SIGNAL CAUSAL BEHAVIORAL NORMALIZATION A/B/C EXPERIMENT")
    print("=" * 80)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    FIG_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load Frozen State Sequences and AR(5) Rollout Engine
    state_file_thu = Path("artifacts/state_sequences/Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl")
    state_file_wed = Path("artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.states.jsonl")
    model_path = Path("artifacts/models/ar5_authoritative")

    print("\n[1/6] Loading frozen states and AR(5) authoritative model...")
    thu_states = load_states_from_jsonl(state_file_thu)
    wed_states = load_states_from_jsonl(state_file_wed)
    ar_model, ar_meta = load_ar_model(model_path)
    rollout_engine = MultiStepRolloutEngine(ar_model=ar_model, feature_names=CSV_AVAILABLE_FEATURES)
    risk_engine = SecurityRiskEngine()

    # Define chronological test split boundaries
    test_cutoff = datetime(2018, 3, 1, 8, 19, 40)
    b4_start = datetime(2018, 3, 1, 9, 57, 0)
    b4_end = datetime(2018, 3, 1, 10, 54, 0)

    thu_test_states = [s for s in thu_states if s.timestamp_start >= test_cutoff and not s.is_empty]
    pre_onset_benign_states = [s for s in thu_test_states if s.timestamp_start < b4_start]
    all_benign_test_states = [s for s in thu_test_states if not (b4_start <= s.timestamp_start <= b4_end)]
    b4_active_states = [s for s in thu_test_states if b4_start <= s.timestamp_start <= b4_end]

    print(f"  Test split states loaded: Thu >= 08:19:40 total={len(thu_test_states)}")
    print(f"  Benign all test windows: N={len(all_benign_test_states)} (pre-onset N={len(pre_onset_benign_states)})")
    print(f"  Block 4 attack windows: N={len(b4_active_states)}")

    # 2. Instantiate Bridges
    bridges = {
        "OLD_STATIC": BehavioralSecurityBridge(),
        "PORT_DYNAMIC": RollingBaselineSecurityBridge(rolling_window_length=30, k_mad=3.0, min_mad=2.0),
        "MULTI_SIGNAL": MultiSignalRollingBaselineSecurityBridge(
            rolling_window_length=30,
            k_mad=3.0,
            scale_floors={"port": 2.0, "flow": 0.30, "byte": 0.80, "timing": 0.50},
            active_signals=("port", "flow", "byte", "timing"),
        ),
    }

    # Helper to evaluate stream
    def run_eval(bridge_inst: BehavioralSecurityBridge, states_seq: Sequence[NetworkState], split_name: str):
        if hasattr(bridge_inst, "reset"):
            bridge_inst.reset()
        return evaluate_sequential_stream(
            states_seq,
            source_split=split_name,
            rollout_engine=rollout_engine,
            bridge=bridge_inst,
            risk_engine=risk_engine,
        )

    results: dict[str, Any] = {
        "metadata": {
            "experiment_id": "bridge_multisignal_experiment_v1",
            "timestamp": datetime.now().isoformat(),
            "random_seed": seed,
            "parameter_selection_provenance": {
                "calibration_dataset": "Thursday-01-03-2018 pre-test window",
                "calibration_time_window": "04:00:00 to 08:00:00 UTC",
                "n_calibration_windows": 625,
                "parameters_selected": {
                    "rolling_window_length": 30,
                    "k_mad": 3.0,
                    "scale_floors": {"port": 2.0, "flow": 0.30, "byte": 0.80, "timing": 0.50},
                    "min_history": 5,
                },
                "calibration_tail_false_rates": {
                    "port": 0.0419,
                    "flow": 0.0384,
                    "byte": 0.0336,
                    "timing": 0.0016,
                },
            },
        },
        "variants": {},
        "ablations": {},
        "experiment_d_contradiction": {},
    }

    # 3. Evaluate Three Primary Variants (A, B, C)
    print("\n[2/6] Evaluating Three Primary Variants (OLD_STATIC, PORT_DYNAMIC, MULTI_SIGNAL)...")
    variant_records = {}

    for name, br in bridges.items():
        print(f"  Evaluating variant: {name}...")

        # Signature trigger rates
        sig_rates_benign = evaluate_signature_rates(br, all_benign_test_states)
        sig_rates_pre = evaluate_signature_rates(br, pre_onset_benign_states)
        sig_rates_b4 = evaluate_signature_rates(br, b4_active_states)

        # Benign all stream
        benign_all_recs = run_eval(br, all_benign_test_states, f"{name}_benign_all")
        benign_all_r0 = [r.r0 for r in benign_all_recs]
        benign_all_stats = compute_distribution_stats(benign_all_r0)
        false_esc_all = count_false_escalation_episodes(benign_all_r0)

        # Benign pre-onset stream
        benign_pre_recs = run_eval(br, pre_onset_benign_states, f"{name}_benign_pre")
        benign_pre_r0 = [r.r0 for r in benign_pre_recs]
        benign_pre_stats = compute_distribution_stats(benign_pre_r0)
        false_esc_pre = count_false_escalation_episodes(benign_pre_r0)

        # Attack Block 4 stream
        b4_recs = run_eval(br, b4_active_states, f"{name}_attack_b4")
        b4_r0 = [r.r0 for r in b4_recs]
        b4_stats = compute_distribution_stats(b4_r0)

        variant_records[name] = {
            "benign_all": benign_all_r0,
            "benign_pre": benign_pre_r0,
            "attack_b4": b4_r0,
        }

        # Individual blocks evaluation
        blocks_data = {}
        all_blocks_r0 = []
        for b_meta in OBSERVED_INFILTRATION_BLOCKS:
            pool = wed_states if b_meta["source_day"] == "Wednesday" else thu_states
            b_st = [s for s in pool if b_meta["start"] <= s.timestamp_start <= b_meta["end"] and not s.is_empty]
            b_eval = run_eval(br, b_st, f"{name}_{b_meta['block_id']}")
            r0_vals = [r.r0 for r in b_eval]
            all_blocks_r0.extend(r0_vals)

            block_comp = moving_block_bootstrap_difference(r0_vals, benign_all_r0, block_size=30, n_boot=1000, seed=seed)
            blocks_data[b_meta["block_id"]] = {
                "name": b_meta["name"],
                "source_day": b_meta["source_day"],
                "window_count": len(b_st),
                "stats": compute_distribution_stats(r0_vals),
                "cohens_d_vs_benign_all": block_comp["cohens_d"],
                "overlap_vs_benign_all": block_comp["overlap_coefficient"],
                "mean_diff_vs_benign_all": block_comp["observed_mean_diff"],
            }

        all_blocks_stats = compute_distribution_stats(all_blocks_r0)

        # Bootstrap Comparisons
        comp_b4_vs_all = moving_block_bootstrap_difference(b4_r0, benign_all_r0, block_size=30, n_boot=2000, seed=seed)
        comp_b4_vs_pre = moving_block_bootstrap_difference(b4_r0, benign_pre_r0, block_size=30, n_boot=2000, seed=seed)
        comp_all_vs_all = moving_block_bootstrap_difference(all_blocks_r0, benign_all_r0, block_size=30, n_boot=2000, seed=seed)
        comp_all_vs_pre = moving_block_bootstrap_difference(all_blocks_r0, benign_pre_r0, block_size=30, n_boot=2000, seed=seed)

        results["variants"][name] = {
            "signature_trigger_rates": {
                "benign_all": sig_rates_benign,
                "benign_pre": sig_rates_pre,
                "attack_b4": sig_rates_b4,
            },
            "benign_all": {
                **benign_all_stats,
                "false_escalation_episodes": false_esc_all,
            },
            "benign_pre": {
                **benign_pre_stats,
                "false_escalation_episodes": false_esc_pre,
            },
            "attack_b4": b4_stats,
            "attack_all_4_blocks": all_blocks_stats,
            "individual_blocks": blocks_data,
            "comparisons": {
                "b4_vs_benign_all": comp_b4_vs_all,
                "b4_vs_benign_pre": comp_b4_vs_pre,
                "all_blocks_vs_benign_all": comp_all_vs_all,
                "all_blocks_vs_benign_pre": comp_all_vs_pre,
            },
        }

    # 4. Multi-Signal Feature Attribution Analysis
    print("\n[3/6] Extracting Multi-Signal Feature Contribution Statistics...")
    # Analyze z-scores and attribution across benign vs attack streams
    ms_bridge = bridges["MULTI_SIGNAL"]
    ms_bridge.reset()

    feat_attr_benign = []
    for st in all_benign_test_states:
        z_dict = ms_bridge.compute_causal_z_scores(st)
        comp_z, prim, contribs = ms_bridge.aggregate_multi_signal_evidence(z_dict)
        feat_attr_benign.append({"z_scores": z_dict, "primary": prim, "composite_z": comp_z, "contributions": contribs})
        ms_bridge.extract_signatures(st, update_baseline=True)

    ms_bridge.reset()
    feat_attr_b4 = []
    for st in b4_active_states:
        z_dict = ms_bridge.compute_causal_z_scores(st)
        comp_z, prim, contribs = ms_bridge.aggregate_multi_signal_evidence(z_dict)
        feat_attr_b4.append({"z_scores": z_dict, "primary": prim, "composite_z": comp_z, "contributions": contribs})
        ms_bridge.extract_signatures(st, update_baseline=True)

    contribution_summary = {}
    for sig_k in ("port", "flow", "byte", "timing"):
        b_z = [item["z_scores"][sig_k] for item in feat_attr_benign]
        a_z = [item["z_scores"][sig_k] for item in feat_attr_b4]
        b_prim_count = sum(1 for item in feat_attr_benign if item["primary"] == sig_k)
        a_prim_count = sum(1 for item in feat_attr_b4 if item["primary"] == sig_k)
        contribution_summary[sig_k] = {
            "benign_mean_z": round(float(np.mean(b_z)), 3),
            "benign_prop_ge_3": round(float(np.mean(np.array(b_z) >= 3.0)), 4),
            "benign_primary_attribution_pct": round(b_prim_count / len(feat_attr_benign) * 100, 1),
            "attack_b4_mean_z": round(float(np.mean(a_z)), 3),
            "attack_b4_prop_ge_3": round(float(np.mean(np.array(a_z) >= 3.0)), 4),
            "attack_b4_primary_attribution_pct": round(a_prim_count / len(feat_attr_b4) * 100, 1),
        }
    results["feature_attribution_summary"] = contribution_summary

    # 5. Signal Ablation Experiment
    print("\n[4/6] Running Systematic Signal Ablation Suite...")
    ablation_configs = {
        "1_PORT_ONLY": ("port",),
        "2_PORT_FLOW": ("port", "flow"),
        "3_PORT_TIMING": ("port", "timing"),
        "4_PORT_BYTE": ("port", "byte"),
        "5_FULL_MULTISIGNAL": ("port", "flow", "byte", "timing"),
    }

    ablation_results = {}
    for abl_name, sig_set in ablation_configs.items():
        print(f"  Evaluating ablation: {abl_name} {sig_set}...")
        abl_br = MultiSignalRollingBaselineSecurityBridge(
            rolling_window_length=30,
            k_mad=3.0,
            active_signals=sig_set,
        )
        b_all_recs = run_eval(abl_br, all_benign_test_states, f"abl_{abl_name}_benign_all")
        b_all_r0 = [r.r0 for r in b_all_recs]
        b_pre_recs = run_eval(abl_br, pre_onset_benign_states, f"abl_{abl_name}_benign_pre")
        b_pre_r0 = [r.r0 for r in b_pre_recs]
        b4_recs = run_eval(abl_br, b4_active_states, f"abl_{abl_name}_b4")
        b4_r0 = [r.r0 for r in b4_recs]

        # Pooled attack across 4 blocks
        all_blocks_r0 = []
        for b_meta in OBSERVED_INFILTRATION_BLOCKS:
            pool = wed_states if b_meta["source_day"] == "Wednesday" else thu_states
            b_st = [s for s in pool if b_meta["start"] <= s.timestamp_start <= b_meta["end"] and not s.is_empty]
            b_eval = run_eval(abl_br, b_st, f"abl_{abl_name}_{b_meta['block_id']}")
            all_blocks_r0.extend([r.r0 for r in b_eval])

        comp_b4_vs_pre = moving_block_bootstrap_difference(b4_r0, b_pre_r0, block_size=30, n_boot=1000, seed=seed)
        comp_all_vs_all = moving_block_bootstrap_difference(all_blocks_r0, b_all_r0, block_size=30, n_boot=1000, seed=seed)

        ablation_results[abl_name] = {
            "active_signals": list(sig_set),
            "benign_all_mean": round(float(np.mean(b_all_r0)), 4),
            "benign_all_median": round(float(np.median(b_all_r0)), 4),
            "pre_onset_mean": round(float(np.mean(b_pre_r0)), 4),
            "pre_onset_median": round(float(np.median(b_pre_r0)), 4),
            "attack_b4_mean": round(float(np.mean(b4_r0)), 4),
            "attack_b4_median": round(float(np.median(b4_r0)), 4),
            "attack_all_mean": round(float(np.mean(all_blocks_r0)), 4),
            "attack_all_median": round(float(np.median(all_blocks_r0)), 4),
            "b4_vs_pre_cohens_d": round(comp_b4_vs_pre["cohens_d"], 4),
            "b4_vs_pre_overlap": round(comp_b4_vs_pre["overlap_coefficient"], 4),
            "b4_vs_pre_mean_diff": round(comp_b4_vs_pre["observed_mean_diff"], 4),
            "b4_vs_pre_mean_diff_ci": [round(x, 4) for x in comp_b4_vs_pre["mean_diff_95ci"]],
            "all_vs_benign_cohens_d": round(comp_all_vs_all["cohens_d"], 4),
            "all_vs_benign_overlap": round(comp_all_vs_all["overlap_coefficient"], 4),
        }
    results["ablations"] = ablation_results

    # 6. Experiment D Contradiction Dynamics Verification
    print("\n[5/6] Verifying Experiment D (Contradiction Dynamics & Safety)...")
    demo_states = get_demo_scenario_states("demo_recon_15s")

    def dynamic_contradiction_trust(idx: int, st: NetworkState, cur_delta: dict[str, float]) -> TrustAssessment:
        port_change = abs(cur_delta.get("dst_port_diversity", 0.0))
        if port_change >= 10.0 and idx >= 8:
            t_val = 0.35
            t_lvl = TrustLevel.LOW
        else:
            t_val = 0.85
            t_lvl = TrustLevel.HIGH

        return TrustAssessment(
            assessment_id=new_id("trust-contra"),
            forecast_id=f"fc-demo-w{idx:02d}",
            forecast_confidence=t_val,
            model_disagreement=0.40 if t_lvl == TrustLevel.LOW else 0.05,
            distribution_shift_score=0.45 if t_lvl == TrustLevel.LOW else 0.05,
            novelty_score=0.30 if t_lvl == TrustLevel.LOW else 0.05,
            historical_error=0.10,
            data_quality=st.data_quality,
            composite_trust=t_val,
            trust_level=t_lvl,
            contributing_factors=(
                TrustFactor(name="reversal_penalty" if t_lvl == TrustLevel.LOW else "historical_error",
                            value=0.40 if t_lvl == TrustLevel.LOW else 0.10,
                            direction=Direction.DECREASES_TRUST if t_lvl == TrustLevel.LOW else Direction.INCREASES_TRUST),
            ),
        )

    exp_d_results = {}
    for name, br in bridges.items():
        if hasattr(br, "reset"):
            br.reset()
        d_recs = evaluate_sequential_stream(
            demo_states,
            source_split="scenario_demo_recon_15s",
            rollout_engine=rollout_engine,
            bridge=br,
            risk_engine=risk_engine,
            dynamic_trust_fn=dynamic_contradiction_trust,
        )
        r0_traj = [r.r0 for r in d_recs]
        trust_traj = [r.composite_trust for r in d_recs]
        escalation_peak = max(r0_traj[6:9])
        contra_trough = min(r0_traj[9:12])
        reversal_reduction = (escalation_peak - contra_trough) / escalation_peak if escalation_peak > 0 else 0.0
        trust_drop_confirmed = min(trust_traj[8:12]) <= 0.35 and max(trust_traj[0:8]) >= 0.85

        exp_d_results[name] = {
            "r0_trajectory": [round(x, 4) for x in r0_traj],
            "trust_trajectory": [round(x, 4) for x in trust_traj],
            "escalation_peak_risk": round(escalation_peak, 4),
            "contradiction_trough_risk": round(contra_trough, 4),
            "reversal_reduction_pct": round(reversal_reduction * 100, 2),
            "trust_drop_confirmed": trust_drop_confirmed,
        }
    results["experiment_d_contradiction"] = exp_d_results

    # 7. Compile Structured CSV Files
    print("\n[6/6] Generating Publication Figures & Exporting CSV Files...")

    # Comparison CSV
    comp_csv_rows = [
        ["Metric", "OLD_STATIC", "PORT_DYNAMIC", "MULTI_SIGNAL"],
        ["Recon Flag Rate (Benign All)", results["variants"]["OLD_STATIC"]["signature_trigger_rates"]["benign_all"]["recon"], results["variants"]["PORT_DYNAMIC"]["signature_trigger_rates"]["benign_all"]["recon"], results["variants"]["MULTI_SIGNAL"]["signature_trigger_rates"]["benign_all"]["recon"]],
        ["Recon Flag Rate (Benign Pre)", results["variants"]["OLD_STATIC"]["signature_trigger_rates"]["benign_pre"]["recon"], results["variants"]["PORT_DYNAMIC"]["signature_trigger_rates"]["benign_pre"]["recon"], results["variants"]["MULTI_SIGNAL"]["signature_trigger_rates"]["benign_pre"]["recon"]],
        ["Recon Flag Rate (Attack B4)", results["variants"]["OLD_STATIC"]["signature_trigger_rates"]["attack_b4"]["recon"], results["variants"]["PORT_DYNAMIC"]["signature_trigger_rates"]["attack_b4"]["recon"], results["variants"]["MULTI_SIGNAL"]["signature_trigger_rates"]["attack_b4"]["recon"]],
        ["Benign Mean R(t)", results["variants"]["OLD_STATIC"]["benign_all"]["mean"], results["variants"]["PORT_DYNAMIC"]["benign_all"]["mean"], results["variants"]["MULTI_SIGNAL"]["benign_all"]["mean"]],
        ["Benign Median R(t)", results["variants"]["OLD_STATIC"]["benign_all"]["median"], results["variants"]["PORT_DYNAMIC"]["benign_all"]["median"], results["variants"]["MULTI_SIGNAL"]["benign_all"]["median"]],
        ["Benign Std R(t)", results["variants"]["OLD_STATIC"]["benign_all"]["std"], results["variants"]["PORT_DYNAMIC"]["benign_all"]["std"], results["variants"]["MULTI_SIGNAL"]["benign_all"]["std"]],
        ["Benign False Escalations (R>=0.50, >=3w)", results["variants"]["OLD_STATIC"]["benign_all"]["false_escalation_episodes"], results["variants"]["PORT_DYNAMIC"]["benign_all"]["false_escalation_episodes"], results["variants"]["MULTI_SIGNAL"]["benign_all"]["false_escalation_episodes"]],
        ["Pre-onset Benign Mean R(t)", results["variants"]["OLD_STATIC"]["benign_pre"]["mean"], results["variants"]["PORT_DYNAMIC"]["benign_pre"]["mean"], results["variants"]["MULTI_SIGNAL"]["benign_pre"]["mean"]],
        ["Pre-onset Benign Median R(t)", results["variants"]["OLD_STATIC"]["benign_pre"]["median"], results["variants"]["PORT_DYNAMIC"]["benign_pre"]["median"], results["variants"]["MULTI_SIGNAL"]["benign_pre"]["median"]],
        ["Attack B4 Mean R(t)", results["variants"]["OLD_STATIC"]["attack_b4"]["mean"], results["variants"]["PORT_DYNAMIC"]["attack_b4"]["mean"], results["variants"]["MULTI_SIGNAL"]["attack_b4"]["mean"]],
        ["Attack B4 Median R(t)", results["variants"]["OLD_STATIC"]["attack_b4"]["median"], results["variants"]["PORT_DYNAMIC"]["attack_b4"]["median"], results["variants"]["MULTI_SIGNAL"]["attack_b4"]["median"]],
        ["Attack All 4 Blocks Mean R(t)", results["variants"]["OLD_STATIC"]["attack_all_4_blocks"]["mean"], results["variants"]["PORT_DYNAMIC"]["attack_all_4_blocks"]["mean"], results["variants"]["MULTI_SIGNAL"]["attack_all_4_blocks"]["mean"]],
        ["Attack All 4 Blocks Median R(t)", results["variants"]["OLD_STATIC"]["attack_all_4_blocks"]["median"], results["variants"]["PORT_DYNAMIC"]["attack_all_4_blocks"]["median"], results["variants"]["MULTI_SIGNAL"]["attack_all_4_blocks"]["median"]],
        ["B4 vs Pre-onset: Observed Mean Diff", results["variants"]["OLD_STATIC"]["comparisons"]["b4_vs_benign_pre"]["observed_mean_diff"], results["variants"]["PORT_DYNAMIC"]["comparisons"]["b4_vs_benign_pre"]["observed_mean_diff"], results["variants"]["MULTI_SIGNAL"]["comparisons"]["b4_vs_benign_pre"]["observed_mean_diff"]],
        ["B4 vs Pre-onset: Mean Diff 95% CI Lower", results["variants"]["OLD_STATIC"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][0], results["variants"]["PORT_DYNAMIC"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][0], results["variants"]["MULTI_SIGNAL"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][0]],
        ["B4 vs Pre-onset: Mean Diff 95% CI Upper", results["variants"]["OLD_STATIC"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][1], results["variants"]["PORT_DYNAMIC"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][1], results["variants"]["MULTI_SIGNAL"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][1]],
        ["B4 vs Pre-onset: Overlap Coefficient", results["variants"]["OLD_STATIC"]["comparisons"]["b4_vs_benign_pre"]["overlap_coefficient"], results["variants"]["PORT_DYNAMIC"]["comparisons"]["b4_vs_benign_pre"]["overlap_coefficient"], results["variants"]["MULTI_SIGNAL"]["comparisons"]["b4_vs_benign_pre"]["overlap_coefficient"]],
        ["B4 vs Pre-onset: Cohen's d", results["variants"]["OLD_STATIC"]["comparisons"]["b4_vs_benign_pre"]["cohens_d"], results["variants"]["PORT_DYNAMIC"]["comparisons"]["b4_vs_benign_pre"]["cohens_d"], results["variants"]["MULTI_SIGNAL"]["comparisons"]["b4_vs_benign_pre"]["cohens_d"]],
        ["All Blocks vs Benign All: Cohen's d", results["variants"]["OLD_STATIC"]["comparisons"]["all_blocks_vs_benign_all"]["cohens_d"], results["variants"]["PORT_DYNAMIC"]["comparisons"]["all_blocks_vs_benign_all"]["cohens_d"], results["variants"]["MULTI_SIGNAL"]["comparisons"]["all_blocks_vs_benign_all"]["cohens_d"]],
        ["All Blocks vs Benign All: Overlap Coef", results["variants"]["OLD_STATIC"]["comparisons"]["all_blocks_vs_benign_all"]["overlap_coefficient"], results["variants"]["PORT_DYNAMIC"]["comparisons"]["all_blocks_vs_benign_all"]["overlap_coefficient"], results["variants"]["MULTI_SIGNAL"]["comparisons"]["all_blocks_vs_benign_all"]["overlap_coefficient"]],
        ["Exp D: Trust Drop Confirmed", results["experiment_d_contradiction"]["OLD_STATIC"]["trust_drop_confirmed"], results["experiment_d_contradiction"]["PORT_DYNAMIC"]["trust_drop_confirmed"], results["experiment_d_contradiction"]["MULTI_SIGNAL"]["trust_drop_confirmed"]],
        ["Exp D: Risk Dampening %", results["experiment_d_contradiction"]["OLD_STATIC"]["reversal_reduction_pct"], results["experiment_d_contradiction"]["PORT_DYNAMIC"]["reversal_reduction_pct"], results["experiment_d_contradiction"]["MULTI_SIGNAL"]["reversal_reduction_pct"]],
    ]
    with open(OUT_DIR / "comparison.csv", "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(comp_csv_rows)

    # Per-Block CSV
    per_block_rows = [["Block ID", "Name", "N", "OLD_Mean", "PORT_Mean", "MULTI_Mean", "OLD_d", "PORT_d", "MULTI_d", "OLD_Overlap", "PORT_Overlap", "MULTI_Overlap"]]
    for b_meta in OBSERVED_INFILTRATION_BLOCKS:
        bid = b_meta["block_id"]
        o_b = results["variants"]["OLD_STATIC"]["individual_blocks"][bid]
        p_b = results["variants"]["PORT_DYNAMIC"]["individual_blocks"][bid]
        m_b = results["variants"]["MULTI_SIGNAL"]["individual_blocks"][bid]
        per_block_rows.append([
            bid, b_meta["name"], o_b["window_count"],
            round(o_b["stats"]["mean"], 4), round(p_b["stats"]["mean"], 4), round(m_b["stats"]["mean"], 4),
            round(o_b["cohens_d_vs_benign_all"], 4), round(p_b["cohens_d_vs_benign_all"], 4), round(m_b["cohens_d_vs_benign_all"], 4),
            round(o_b["overlap_vs_benign_all"], 4), round(p_b["overlap_vs_benign_all"], 4), round(m_b["overlap_vs_benign_all"], 4),
        ])
    with open(OUT_DIR / "per_block.csv", "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(per_block_rows)

    # Pre-onset Comparison CSV
    pre_onset_rows = [
        ["Configuration", "Pre_Onset_Mean", "Attack_B4_Mean", "Mean_Diff", "Mean_Diff_CI_Lower", "Mean_Diff_CI_Upper", "Cohens_d", "Overlap_Coef"],
        ["OLD_STATIC", results["variants"]["OLD_STATIC"]["benign_pre"]["mean"], results["variants"]["OLD_STATIC"]["attack_b4"]["mean"], results["variants"]["OLD_STATIC"]["comparisons"]["b4_vs_benign_pre"]["observed_mean_diff"], results["variants"]["OLD_STATIC"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][0], results["variants"]["OLD_STATIC"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][1], results["variants"]["OLD_STATIC"]["comparisons"]["b4_vs_benign_pre"]["cohens_d"], results["variants"]["OLD_STATIC"]["comparisons"]["b4_vs_benign_pre"]["overlap_coefficient"]],
        ["PORT_DYNAMIC", results["variants"]["PORT_DYNAMIC"]["benign_pre"]["mean"], results["variants"]["PORT_DYNAMIC"]["attack_b4"]["mean"], results["variants"]["PORT_DYNAMIC"]["comparisons"]["b4_vs_benign_pre"]["observed_mean_diff"], results["variants"]["PORT_DYNAMIC"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][0], results["variants"]["PORT_DYNAMIC"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][1], results["variants"]["PORT_DYNAMIC"]["comparisons"]["b4_vs_benign_pre"]["cohens_d"], results["variants"]["PORT_DYNAMIC"]["comparisons"]["b4_vs_benign_pre"]["overlap_coefficient"]],
        ["MULTI_SIGNAL", results["variants"]["MULTI_SIGNAL"]["benign_pre"]["mean"], results["variants"]["MULTI_SIGNAL"]["attack_b4"]["mean"], results["variants"]["MULTI_SIGNAL"]["comparisons"]["b4_vs_benign_pre"]["observed_mean_diff"], results["variants"]["MULTI_SIGNAL"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][0], results["variants"]["MULTI_SIGNAL"]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][1], results["variants"]["MULTI_SIGNAL"]["comparisons"]["b4_vs_benign_pre"]["cohens_d"], results["variants"]["MULTI_SIGNAL"]["comparisons"]["b4_vs_benign_pre"]["overlap_coefficient"]],
    ]
    with open(OUT_DIR / "pre_onset_comparison.csv", "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(pre_onset_rows)

    # Ablation Results CSV
    ablation_rows = [["Ablation_Name", "Signals", "Benign_Mean", "Pre_Onset_Mean", "Attack_B4_Mean", "Attack_All_Mean", "B4_vs_Pre_Cohens_d", "B4_vs_Pre_Overlap", "All_vs_Benign_Cohens_d", "All_vs_Benign_Overlap"]]
    for abl_k, abl_v in ablation_results.items():
        ablation_rows.append([
            abl_k, "+".join(abl_v["active_signals"]),
            abl_v["benign_all_mean"], abl_v["pre_onset_mean"], abl_v["attack_b4_mean"], abl_v["attack_all_mean"],
            abl_v["b4_vs_pre_cohens_d"], abl_v["b4_vs_pre_overlap"],
            abl_v["all_vs_benign_cohens_d"], abl_v["all_vs_benign_overlap"],
        ])
    with open(OUT_DIR / "ablation_results.csv", "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(ablation_rows)

    # Feature Contributions CSV
    feat_contrib_rows = [["Signal", "Benign_Mean_Z", "Benign_Prop_GE_3", "Benign_Primary_Attribution_Pct", "Attack_B4_Mean_Z", "Attack_B4_Prop_GE_3", "Attack_B4_Primary_Attribution_Pct"]]
    for sig_k, s_dict in contribution_summary.items():
        feat_contrib_rows.append([
            sig_k, s_dict["benign_mean_z"], s_dict["benign_prop_ge_3"], s_dict["benign_primary_attribution_pct"],
            s_dict["attack_b4_mean_z"], s_dict["attack_b4_prop_ge_3"], s_dict["attack_b4_primary_attribution_pct"],
        ])
    with open(OUT_DIR / "feature_contributions.csv", "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(feat_contrib_rows)

    # Trajectory CSVs
    with open(OUT_DIR / "trajectory_benign.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Window_Index", "OLD_STATIC", "PORT_DYNAMIC", "MULTI_SIGNAL"])
        for idx in range(len(variant_records["OLD_STATIC"]["benign_all"])):
            writer.writerow([idx, round(variant_records["OLD_STATIC"]["benign_all"][idx], 4), round(variant_records["PORT_DYNAMIC"]["benign_all"][idx], 4), round(variant_records["MULTI_SIGNAL"]["benign_all"][idx], 4)])

    with open(OUT_DIR / "trajectory_attack_b4.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Window_Index", "OLD_STATIC", "PORT_DYNAMIC", "MULTI_SIGNAL"])
        for idx in range(len(variant_records["OLD_STATIC"]["attack_b4"])):
            writer.writerow([idx, round(variant_records["OLD_STATIC"]["attack_b4"][idx], 4), round(variant_records["PORT_DYNAMIC"]["attack_b4"][idx], 4), round(variant_records["MULTI_SIGNAL"]["attack_b4"][idx], 4)])

    with open(OUT_DIR / "trajectory_contradiction.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Step_Index", "Trust", "OLD_STATIC_R0", "PORT_DYNAMIC_R0", "MULTI_SIGNAL_R0"])
        d_len = len(exp_d_results["OLD_STATIC"]["r0_trajectory"])
        for idx in range(d_len):
            writer.writerow([
                idx, exp_d_results["MULTI_SIGNAL"]["trust_trajectory"][idx],
                exp_d_results["OLD_STATIC"]["r0_trajectory"][idx],
                exp_d_results["PORT_DYNAMIC"]["r0_trajectory"][idx],
                exp_d_results["MULTI_SIGNAL"]["r0_trajectory"][idx],
            ])

    # 8. Save Complete JSON Manifests
    with open(OUT_DIR / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    with open(OUT_DIR / "results_summary.json", "w", encoding="utf-8") as f:
        json.dump({
            "experiment_id": "bridge_multisignal_experiment_v1",
            "status": "COMPLETED",
            "variants_summary": {
                name: {
                    "benign_mean_risk": results["variants"][name]["benign_all"]["mean"],
                    "benign_median_risk": results["variants"][name]["benign_all"]["median"],
                    "pre_onset_mean_risk": results["variants"][name]["benign_pre"]["mean"],
                    "attack_b4_mean_risk": results["variants"][name]["attack_b4"]["mean"],
                    "b4_vs_pre_cohens_d": results["variants"][name]["comparisons"]["b4_vs_benign_pre"]["cohens_d"],
                    "b4_vs_pre_overlap": results["variants"][name]["comparisons"]["b4_vs_benign_pre"]["overlap_coefficient"],
                    "all_vs_benign_cohens_d": results["variants"][name]["comparisons"]["all_blocks_vs_benign_all"]["cohens_d"],
                    "all_vs_benign_overlap": results["variants"][name]["comparisons"]["all_blocks_vs_benign_all"]["overlap_coefficient"],
                }
                for name in ("OLD_STATIC", "PORT_DYNAMIC", "MULTI_SIGNAL")
            },
            "ablations": ablation_results,
            "contradiction_regression": {
                name: exp_d_results[name]["reversal_reduction_pct"]
                for name in ("OLD_STATIC", "PORT_DYNAMIC", "MULTI_SIGNAL")
            },
        }, f, indent=2)

    # 9. Generate 8 Publication-Quality Plots
    # Plot 1: Benign R(t) trajectories
    fig, ax = plt.subplots(figsize=(12, 5), dpi=300)
    idx_arr = np.arange(len(variant_records["OLD_STATIC"]["benign_all"]))
    ax.plot(idx_arr[:300], variant_records["OLD_STATIC"]["benign_all"][:300], label="OLD Static Bridge", color="#94A3B8", alpha=0.8, linewidth=1.2)
    ax.plot(idx_arr[:300], variant_records["PORT_DYNAMIC"]["benign_all"][:300], label="PORT-DYNAMIC Bridge", color="#3B82F6", alpha=0.85, linewidth=1.2)
    ax.plot(idx_arr[:300], variant_records["MULTI_SIGNAL"]["benign_all"][:300], label="MULTI-SIGNAL Bridge", color="#10B981", alpha=0.9, linewidth=1.5)
    ax.axhline(0.50, color="#EF4444", linestyle=":", label="Medium Risk Threshold (0.50)")
    ax.set_title("Plot 1: Benign Risk Trajectory R(t) — First 300 Windows", fontsize=11, fontweight="bold")
    ax.set_xlabel("Chronological Window Index (10s per window)", fontsize=9)
    ax.set_ylabel("Security Risk Score R(t)", fontsize=9)
    ax.set_ylim(-0.02, 1.02)
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend(loc="upper right", fontsize=8)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "01_benign_risk_trajectories.png", dpi=300)
    plt.close()

    # Plot 2: Attack Block 4 trajectories
    fig, ax = plt.subplots(figsize=(12, 5), dpi=300)
    b4_idx = np.arange(len(variant_records["OLD_STATIC"]["attack_b4"]))
    ax.plot(b4_idx, variant_records["OLD_STATIC"]["attack_b4"], label="OLD Static Bridge", color="#94A3B8", alpha=0.8, linewidth=1.2)
    ax.plot(b4_idx, variant_records["PORT_DYNAMIC"]["attack_b4"], label="PORT-DYNAMIC Bridge", color="#3B82F6", alpha=0.85, linewidth=1.2)
    ax.plot(b4_idx, variant_records["MULTI_SIGNAL"]["attack_b4"], label="MULTI-SIGNAL Bridge", color="#10B981", alpha=0.9, linewidth=1.5)
    ax.set_title("Plot 2: Attack Block 4 Trajectory R(t) (Thursday 09:57 - 10:54)", fontsize=11, fontweight="bold")
    ax.set_xlabel("Window Index within Block 4", fontsize=9)
    ax.set_ylabel("Security Risk Score R(t)", fontsize=9)
    ax.set_ylim(-0.02, 1.02)
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend(loc="upper right", fontsize=8)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "02_attack_b4_risk_trajectories.png", dpi=300)
    plt.close()

    # Plot 3: Primary Pre-Onset Comparison (Distributions & Bootstrap CIs)
    fig, (ax_d, ax_ci) = plt.subplots(1, 2, figsize=(13, 5), dpi=300)
    bins = np.linspace(0, 1, 35)
    ax_d.hist(variant_records["MULTI_SIGNAL"]["benign_pre"], bins=bins, alpha=0.45, density=True, color="#3B82F6", label="Pre-Onset Benign (N=584)")
    ax_d.hist(variant_records["MULTI_SIGNAL"]["attack_b4"], bins=bins, alpha=0.45, density=True, color="#EF4444", label="Attack Block 4 (N=343)")
    ax_d.set_title("MULTI-SIGNAL: Pre-Onset vs Block 4 Density", fontsize=10, fontweight="bold")
    ax_d.set_xlabel("Risk Score R(t)", fontsize=9)
    ax_d.set_ylabel("Density", fontsize=9)
    ax_d.grid(True, linestyle="--", alpha=0.4)
    ax_d.legend(loc="upper right", fontsize=8)

    labels = ["OLD Static", "PORT-Dynamic", "MULTI-Signal"]
    diffs = [results["variants"][v]["comparisons"]["b4_vs_benign_pre"]["observed_mean_diff"] for v in ("OLD_STATIC", "PORT_DYNAMIC", "MULTI_SIGNAL")]
    ci_low = [results["variants"][v]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][0] for v in ("OLD_STATIC", "PORT_DYNAMIC", "MULTI_SIGNAL")]
    ci_high = [results["variants"][v]["comparisons"]["b4_vs_benign_pre"]["mean_diff_95ci"][1] for v in ("OLD_STATIC", "PORT_DYNAMIC", "MULTI_SIGNAL")]
    y_pos = np.arange(len(labels))
    x_err = [np.array(diffs) - np.array(ci_low), np.array(ci_high) - np.array(diffs)]
    ax_ci.errorbar(diffs, y_pos, xerr=x_err, fmt='o', color="#1E3A8A", ecolor="#EF4444", elinewidth=2, capsize=5, markersize=7)
    ax_ci.axvline(0.0, color="black", linestyle="--", alpha=0.7)
    ax_ci.set_yticks(y_pos)
    ax_ci.set_yticklabels(labels, fontsize=9)
    ax_ci.set_xlabel("Mean Risk Difference (Block 4 - Pre-Onset)", fontsize=9)
    ax_ci.set_title("Plot 3: 95% Moving Block Bootstrap CIs (B=30)", fontsize=10, fontweight="bold")
    ax_ci.grid(True, linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "03_primary_pre_onset_comparison.png", dpi=300)
    plt.close()

    # Plot 4: Per-Block Cohen's d
    fig, ax = plt.subplots(figsize=(10, 5), dpi=300)
    b_ids = [b["block_id"] for b in OBSERVED_INFILTRATION_BLOCKS]
    x = np.arange(len(b_ids))
    width = 0.25
    d_old = [results["variants"]["OLD_STATIC"]["individual_blocks"][bid]["cohens_d_vs_benign_all"] for bid in b_ids]
    d_port = [results["variants"]["PORT_DYNAMIC"]["individual_blocks"][bid]["cohens_d_vs_benign_all"] for bid in b_ids]
    d_multi = [results["variants"]["MULTI_SIGNAL"]["individual_blocks"][bid]["cohens_d_vs_benign_all"] for bid in b_ids]
    ax.bar(x - width, d_old, width, label="OLD Static", color="#94A3B8")
    ax.bar(x, d_port, width, label="PORT-Dynamic", color="#3B82F6")
    ax.bar(x + width, d_multi, width, label="MULTI-Signal", color="#10B981")
    ax.set_xticks(x)
    ax.set_xticklabels(["Wed B1", "Wed B2", "Thu B3", "Thu B4"], fontsize=9)
    ax.set_ylabel("Cohen's d vs Benign All", fontsize=9)
    ax.set_title("Plot 4: Per-Block Effect Size (Cohen's d)", fontsize=11, fontweight="bold")
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend(loc="upper left", fontsize=8)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "04_per_block_cohens_d.png", dpi=300)
    plt.close()

    # Plot 5: Per-Block Overlap %
    fig, ax = plt.subplots(figsize=(10, 5), dpi=300)
    ov_old = [results["variants"]["OLD_STATIC"]["individual_blocks"][bid]["overlap_vs_benign_all"] * 100 for bid in b_ids]
    ov_port = [results["variants"]["PORT_DYNAMIC"]["individual_blocks"][bid]["overlap_vs_benign_all"] * 100 for bid in b_ids]
    ov_multi = [results["variants"]["MULTI_SIGNAL"]["individual_blocks"][bid]["overlap_vs_benign_all"] * 100 for bid in b_ids]
    ax.bar(x - width, ov_old, width, label="OLD Static", color="#F87171")
    ax.bar(x, ov_port, width, label="PORT-Dynamic", color="#60A5FA")
    ax.bar(x + width, ov_multi, width, label="MULTI-Signal", color="#34D399")
    ax.set_xticks(x)
    ax.set_xticklabels(["Wed B1", "Wed B2", "Thu B3", "Thu B4"], fontsize=9)
    ax.set_ylabel("Distribution Overlap % (Lower is Better)", fontsize=9)
    ax.set_ylim(0, 100)
    ax.set_title("Plot 5: Per-Block Distribution Overlap %", fontsize=11, fontweight="bold")
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend(loc="upper right", fontsize=8)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "05_per_block_overlap.png", dpi=300)
    plt.close()

    # Plot 6: Signal Ablation Performance
    fig, ax = plt.subplots(figsize=(11, 5), dpi=300)
    abl_keys = list(ablation_results.keys())
    x_abl = np.arange(len(abl_keys))
    d_b4_pre = [ablation_results[k]["b4_vs_pre_cohens_d"] for k in abl_keys]
    d_all_ben = [ablation_results[k]["all_vs_benign_cohens_d"] for k in abl_keys]
    width = 0.35
    ax.bar(x_abl - width/2, d_b4_pre, width, label="B4 vs Pre-Onset Cohen's d", color="#F59E0B")
    ax.bar(x_abl + width/2, d_all_ben, width, label="All Blocks vs Benign Cohen's d", color="#6366F1")
    ax.set_xticks(x_abl)
    ax.set_xticklabels(["Port Only", "Port+Flow", "Port+Timing", "Port+Byte", "Full Multi"], fontsize=9)
    ax.set_ylabel("Cohen's d", fontsize=9)
    ax.set_title("Plot 6: Signal Ablation — Marginal Contributions", fontsize=11, fontweight="bold")
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend(loc="upper left", fontsize=8)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "06_signal_ablation_performance.png", dpi=300)
    plt.close()

    # Plot 7: Multi-Signal Contribution Breakdown
    fig, ax = plt.subplots(figsize=(9, 5), dpi=300)
    sig_labels = ["Port", "Flow", "Byte", "Timing"]
    b_prop = [contribution_summary[k]["benign_prop_ge_3"] * 100 for k in ("port", "flow", "byte", "timing")]
    a_prop = [contribution_summary[k]["attack_b4_prop_ge_3"] * 100 for k in ("port", "flow", "byte", "timing")]
    x_sig = np.arange(len(sig_labels))
    width = 0.35
    ax.bar(x_sig - width/2, b_prop, width, label="Benign Baseline % (z >= 3.0)", color="#94A3B8")
    ax.bar(x_sig + width/2, a_prop, width, label="Attack Block 4 % (z >= 3.0)", color="#EF4444")
    ax.set_xticks(x_sig)
    ax.set_xticklabels(sig_labels, fontsize=9)
    ax.set_ylabel("Proportion Exceeding 3.0 MAD Tail (%)", fontsize=9)
    ax.set_title("Plot 7: Anomaly Frequency Breakdown by Dimension", fontsize=11, fontweight="bold")
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend(loc="upper right", fontsize=8)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "07_multisignal_contribution_breakdown.png", dpi=300)
    plt.close()

    # Plot 8: Contradiction Regression (Experiment D)
    fig, ax = plt.subplots(figsize=(11, 5), dpi=300)
    steps = np.arange(len(exp_d_results["OLD_STATIC"]["r0_trajectory"]))
    ax.plot(steps, exp_d_results["OLD_STATIC"]["r0_trajectory"], label="OLD Static R(t)", color="#94A3B8", linewidth=1.5)
    ax.plot(steps, exp_d_results["PORT_DYNAMIC"]["r0_trajectory"], label="PORT-Dynamic R(t)", color="#3B82F6", linewidth=1.5)
    ax.plot(steps, exp_d_results["MULTI_SIGNAL"]["r0_trajectory"], label="MULTI-Signal R(t)", color="#10B981", linewidth=2.0)
    ax.plot(steps, exp_d_results["MULTI_SIGNAL"]["trust_trajectory"], label="Composite Trust", color="#D97706", linestyle="--", linewidth=1.5)
    ax.axvspan(6, 8, alpha=0.15, color="red", label="Escalation Phase")
    ax.axvspan(9, 11, alpha=0.15, color="blue", label="Contradiction Phase")
    ax.set_title("Plot 8: Experiment D Contradiction Reversal & Risk Dampening", fontsize=11, fontweight="bold")
    ax.set_xlabel("Scenario Step Index", fontsize=9)
    ax.set_ylabel("Score", fontsize=9)
    ax.set_ylim(-0.02, 1.02)
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend(loc="upper right", fontsize=8)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "08_contradiction_regression.png", dpi=300)
    plt.close()

    print(f"  All 8 plots successfully saved to: {FIG_DIR}")

    # 10. Print Comprehensive Output Table
    print("\n" + "=" * 90)
    print("A/B/C COMPARISON RESULTS TABLE")
    print("=" * 90)
    fmt_header = f"{'Metric':<42} | {'OLD_STATIC':<14} | {'PORT_DYNAMIC':<14} | {'MULTI_SIGNAL':<14}"
    print(fmt_header)
    print("-" * len(fmt_header))
    for row in comp_csv_rows[1:]:
        m, o, p, ms = row[0], str(row[1]), str(row[2]), str(row[3])
        if isinstance(row[1], float): o = f"{row[1]:.4f}"
        if isinstance(row[2], float): p = f"{row[2]:.4f}"
        if isinstance(row[3], float): ms = f"{row[3]:.4f}"
        print(f"{m:<42} | {o:<14} | {p:<14} | {ms:<14}")
    print("=" * 90)

    print("\nSIGNAL ABLATION BREAKDOWN:")
    print(f"{'Ablation':<20} | {'Signals':<18} | {'Pre-Onset R':<11} | {'B4 Attack R':<11} | {'B4 vs Pre d':<11} | {'All vs Ben d':<12}")
    print("-" * 90)
    for abl_k, abl_v in ablation_results.items():
        print(f"{abl_k:<20} | {'+'.join(abl_v['active_signals']):<18} | {abl_v['pre_onset_mean']:<11.4f} | {abl_v['attack_b4_mean']:<11.4f} | {abl_v['b4_vs_pre_cohens_d']:<+11.4f} | {abl_v['all_vs_benign_cohens_d']:<+12.4f}")
    print("=" * 90)

    return results


if __name__ == "__main__":
    run_multisignal_experiment()
