"""
A/B Empirical Validation Experiment: Static vs Dynamic Rolling-Baseline Thresholding in BehavioralSecurityBridge.

SIH PS 26153: AI-Based Network Attack Forecasting from Network Traffic Data.

Strict Experimental Protocol:
- Models, state loading, rollout engine, and risk engine logic are FROZEN.
- Parameter selection for rolling baseline (W=30, k=3.0, min_mad=2.0) was performed strictly
  on pre-test split data (Thursday 04:00:00 to 08:00:00 UTC, N=625 windows).
- Evaluates both OLD (static thresholds >=15, >=8) and NEW (dynamic rolling baseline)
  on the exact same chronological test split populations:
  * Benign all test windows (N=1339)
  * Pre-onset benign context windows (N=584)
  * Block 4 infiltration attack (N=343)
  * All 4 infiltration blocks pooled (N=1708)
  * Per-block evaluation across all 4 infiltration blocks
- Preserves temporal autocorrelation using Moving Block Bootstrap (block=30 windows / 300s, 2000 resamples).
- Verifies Experiment D contradiction dynamics to prevent regression.
"""
from __future__ import annotations

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
from security.contracts import SignatureType
from security.risk_engine import SecurityRiskEngine


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


def evaluate_recon_signature_rate(bridge: BehavioralSecurityBridge, states: Sequence[NetworkState]) -> float:
    """Computes the proportion of windows where RECONNAISSANCE_PORT_EXPLORATION signature is triggered."""
    if hasattr(bridge, "reset"):
        bridge.reset()
    count = 0
    for st in states:
        sigs = bridge.extract_signatures(st)
        if any(s.signature_type == SignatureType.RECONNAISSANCE_PORT_EXPLORATION for s in sigs):
            count += 1
    return count / len(states) if states else 0.0


def run_ab_experiment(seed: int = 42) -> dict[str, Any]:
    print("=" * 80)
    print("SIH PS 26153: A/B EXPERIMENT — STATIC VS DYNAMIC ROLLING-BASELINE THRESHOLDING")
    print("=" * 80)

    # 1. Load Frozen State Sequences and AR(5) Rollout Engine
    state_file_thu = Path("artifacts/state_sequences/Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl")
    state_file_wed = Path("artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.states.jsonl")
    model_path = Path("artifacts/models/ar5_authoritative")

    print("\n[1/6] Loading frozen states and AR(5) model...")
    thu_states = load_states_from_jsonl(state_file_thu)
    wed_states = load_states_from_jsonl(state_file_wed)
    ar_model, ar_meta = load_ar_model(model_path)
    rollout_engine = MultiStepRolloutEngine(ar_model=ar_model, feature_names=CSV_AVAILABLE_FEATURES)
    risk_engine = SecurityRiskEngine()

    # Define test split
    test_cutoff = datetime(2018, 3, 1, 8, 19, 40)
    b4_start = datetime(2018, 3, 1, 9, 57, 0)
    b4_end = datetime(2018, 3, 1, 10, 54, 0)

    thu_test_states = [s for s in thu_states if s.timestamp_start >= test_cutoff and not s.is_empty]
    pre_onset_benign_states = [s for s in thu_test_states if s.timestamp_start < b4_start]
    all_benign_test_states = [s for s in thu_test_states if not (b4_start <= s.timestamp_start <= b4_end)]
    b4_active_states = [s for s in thu_test_states if b4_start <= s.timestamp_start <= b4_end]

    print(f"  Test split states loaded: Thu >= 08:19:40 total={len(thu_test_states)}")
    print(f"  Benign test windows: N={len(all_benign_test_states)} (pre-onset N={len(pre_onset_benign_states)})")
    print(f"  Block 4 attack windows: N={len(b4_active_states)}")

    # 2. Instantiate Bridges
    # OLD: Static BehavioralSecurityBridge
    old_bridge = BehavioralSecurityBridge()
    # NEW: Dynamic RollingBaselineSecurityBridge (W=30, k=3.0, min_mad=2.0)
    new_bridge = RollingBaselineSecurityBridge(
        rolling_window_length=30,
        k_mad=3.0,
        min_mad=2.0,
        min_history=5,
        static_fallback_threshold=15.0,
    )

    bridges = {
        "OLD_STATIC": old_bridge,
        "NEW_ROLLING": new_bridge,
    }

    results: dict[str, Any] = {
        "metadata": {
            "experiment_id": "bridge_ab_experiment_v1",
            "timestamp": datetime.now().isoformat(),
            "random_seed": seed,
            "parameter_selection_provenance": {
                "dataset": "Thursday-01-03-2018 pre-test window",
                "time_window": "04:00:00 to 08:00:00 UTC",
                "n_windows": 625,
                "background_median_port_div": 18.0,
                "background_mean_port_div": 25.55,
                "background_mad_port_div": 3.0,
                "parameters_selected": {
                    "rolling_window_length": 30,
                    "k_mad": 3.0,
                    "min_mad": 2.0,
                },
                "pre_test_false_recon_rate_static": 0.8128,
                "pre_test_false_recon_rate_rolling": 0.0419,
            },
        },
        "bridges": {},
        "comparison": {},
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

    # 3. Evaluate Both Bridges on Test Populations
    for name, br in bridges.items():
        print(f"\n[2/6] Evaluating Bridge: {name}...")

        # Reconnaissance signature trigger rate on benign
        recon_rate_benign = evaluate_recon_signature_rate(br, all_benign_test_states)
        recon_rate_pre = evaluate_recon_signature_rate(br, pre_onset_benign_states)
        recon_rate_b4 = evaluate_recon_signature_rate(br, b4_active_states)

        # Benign all
        benign_all_recs = run_eval(br, all_benign_test_states, f"{name}_benign_all")
        benign_all_r0 = [r.r0 for r in benign_all_recs]
        benign_all_stats = compute_distribution_stats(benign_all_r0)
        false_esc_all = count_false_escalation_episodes(benign_all_r0)

        # Benign pre-onset
        benign_pre_recs = run_eval(br, pre_onset_benign_states, f"{name}_benign_pre")
        benign_pre_r0 = [r.r0 for r in benign_pre_recs]
        benign_pre_stats = compute_distribution_stats(benign_pre_r0)
        false_esc_pre = count_false_escalation_episodes(benign_pre_r0)

        # Attack Block 4
        b4_recs = run_eval(br, b4_active_states, f"{name}_attack_b4")
        b4_r0 = [r.r0 for r in b4_recs]
        b4_stats = compute_distribution_stats(b4_r0)

        # All 4 infiltration blocks individually
        blocks_data = {}
        all_blocks_r0 = []
        for b_meta in OBSERVED_INFILTRATION_BLOCKS:
            pool = wed_states if b_meta["source_day"] == "Wednesday" else thu_states
            b_st = [s for s in pool if b_meta["start"] <= s.timestamp_start <= b_meta["end"] and not s.is_empty]
            b_eval = run_eval(br, b_st, f"{name}_{b_meta['block_id']}")
            r0_vals = [r.r0 for r in b_eval]
            all_blocks_r0.extend(r0_vals)
            recon_rate_block = evaluate_recon_signature_rate(br, b_st)

            # Difference vs benign all for this block
            block_vs_benign = moving_block_bootstrap_difference(r0_vals, benign_all_r0, block_size=30, n_boot=1000, seed=seed)

            blocks_data[b_meta["block_id"]] = {
                "name": b_meta["name"],
                "source_day": b_meta["source_day"],
                "window_count": len(b_st),
                "stats": compute_distribution_stats(r0_vals),
                "recon_signature_rate": recon_rate_block,
                "cohens_d_vs_benign_all": block_vs_benign["cohens_d"],
                "overlap_vs_benign_all": block_vs_benign["overlap_coefficient"],
                "mean_diff_vs_benign_all": block_vs_benign["observed_mean_diff"],
            }

        all_blocks_stats = compute_distribution_stats(all_blocks_r0)

        # Bootstrap comparison: B4 vs Benign All
        comp_b4_vs_all = moving_block_bootstrap_difference(b4_r0, benign_all_r0, block_size=30, n_boot=2000, seed=seed)
        # Bootstrap comparison: B4 vs Pre-onset Benign (the primary benchmark)
        comp_b4_vs_pre = moving_block_bootstrap_difference(b4_r0, benign_pre_r0, block_size=30, n_boot=2000, seed=seed)
        # Bootstrap comparison: All Blocks vs Benign All
        comp_all_vs_all = moving_block_bootstrap_difference(all_blocks_r0, benign_all_r0, block_size=30, n_boot=2000, seed=seed)
        # Bootstrap comparison: All Blocks vs Pre-onset Benign
        comp_all_vs_pre = moving_block_bootstrap_difference(all_blocks_r0, benign_pre_r0, block_size=30, n_boot=2000, seed=seed)

        results["bridges"][name] = {
            "recon_signature_rates": {
                "benign_all": recon_rate_benign,
                "benign_pre": recon_rate_pre,
                "attack_b4": recon_rate_b4,
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

    # 4. Evaluate Experiment D (Contradiction Dynamics Regression Check)
    print("\n[3/6] Verifying Experiment D (Contradiction Dynamics)...")
    demo_states = get_demo_scenario_states("demo_recon_15s")

    def dynamic_contradiction_trust(idx: int, st: NetworkState, cur_delta: dict[str, float]) -> TrustAssessment:
        port_change = abs(cur_delta.get("dst_port_diversity", 0.0))
        if port_change >= 10.0 and idx >= 8:
            t_val = 0.35
            t_lvl = TrustLevel.LOW
        elif port_change >= 15.0:
            t_val = 0.65
            t_lvl = TrustLevel.MEDIUM
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
        
        # Canonical phase boundaries:
        # Phase 3 (Escalation): indices 6 to 8
        # Phase 4 (Contradiction reversal): indices 9 to 11
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

    results["experiment_d_regression_check"] = exp_d_results

    # 5. Compile Comparison Summary Table
    old_res = results["bridges"]["OLD_STATIC"]
    new_res = results["bridges"]["NEW_ROLLING"]

    summary_table = {
        "Metric": [
            "Recon Flag Rate (Benign All, N=1339)",
            "Recon Flag Rate (Benign Pre, N=584)",
            "Recon Flag Rate (Attack B4, N=343)",
            "Benign Mean R(t)",
            "Benign Median R(t)",
            "Benign Std R(t)",
            "Benign False Escalations (R>=0.50, >=3w)",
            "Pre-onset Benign Mean R(t)",
            "Pre-onset Benign Median R(t)",
            "Attack B4 Mean R(t)",
            "Attack B4 Median R(t)",
            "Attack All 4 Blocks Mean R(t)",
            "Attack All 4 Blocks Median R(t)",
            "B4 vs Benign All: Observed Mean Diff",
            "B4 vs Benign All: Mean Diff 95% CI",
            "B4 vs Benign All: Overlap Coefficient",
            "B4 vs Benign All: Cohen's d",
            "B4 vs Pre-onset: Observed Mean Diff",
            "B4 vs Pre-onset: Mean Diff 95% CI",
            "B4 vs Pre-onset: Overlap Coefficient",
            "B4 vs Pre-onset: Cohen's d",
            "All Blocks vs Benign All: Cohen's d",
            "All Blocks vs Benign All: Overlap Coef",
            "Exp D: Trust Drop Confirmed",
            "Exp D: Risk Dampening % post-reversal",
        ],
        "OLD_STATIC": [
            f"{old_res['recon_signature_rates']['benign_all']*100:.1f}%",
            f"{old_res['recon_signature_rates']['benign_pre']*100:.1f}%",
            f"{old_res['recon_signature_rates']['attack_b4']*100:.1f}%",
            f"{old_res['benign_all']['mean']:.4f}",
            f"{old_res['benign_all']['median']:.4f}",
            f"{old_res['benign_all']['std']:.4f}",
            f"{old_res['benign_all']['false_escalation_episodes']}",
            f"{old_res['benign_pre']['mean']:.4f}",
            f"{old_res['benign_pre']['median']:.4f}",
            f"{old_res['attack_b4']['mean']:.4f}",
            f"{old_res['attack_b4']['median']:.4f}",
            f"{old_res['attack_all_4_blocks']['mean']:.4f}",
            f"{old_res['attack_all_4_blocks']['median']:.4f}",
            f"{old_res['comparisons']['b4_vs_benign_all']['observed_mean_diff']:+.4f}",
            f"[{old_res['comparisons']['b4_vs_benign_all']['mean_diff_95ci'][0]:+.4f}, {old_res['comparisons']['b4_vs_benign_all']['mean_diff_95ci'][1]:+.4f}]",
            f"{old_res['comparisons']['b4_vs_benign_all']['overlap_coefficient']:.4f}",
            f"{old_res['comparisons']['b4_vs_benign_all']['cohens_d']:.4f}",
            f"{old_res['comparisons']['b4_vs_benign_pre']['observed_mean_diff']:+.4f}",
            f"[{old_res['comparisons']['b4_vs_benign_pre']['mean_diff_95ci'][0]:+.4f}, {old_res['comparisons']['b4_vs_benign_pre']['mean_diff_95ci'][1]:+.4f}]",
            f"{old_res['comparisons']['b4_vs_benign_pre']['overlap_coefficient']:.4f}",
            f"{old_res['comparisons']['b4_vs_benign_pre']['cohens_d']:.4f}",
            f"{old_res['comparisons']['all_blocks_vs_benign_all']['cohens_d']:.4f}",
            f"{old_res['comparisons']['all_blocks_vs_benign_all']['overlap_coefficient']:.4f}",
            f"{exp_d_results['OLD_STATIC']['trust_drop_confirmed']}",
            f"{exp_d_results['OLD_STATIC']['reversal_reduction_pct']:.1f}%",
        ],
        "NEW_ROLLING": [
            f"{new_res['recon_signature_rates']['benign_all']*100:.1f}%",
            f"{new_res['recon_signature_rates']['benign_pre']*100:.1f}%",
            f"{new_res['recon_signature_rates']['attack_b4']*100:.1f}%",
            f"{new_res['benign_all']['mean']:.4f}",
            f"{new_res['benign_all']['median']:.4f}",
            f"{new_res['benign_all']['std']:.4f}",
            f"{new_res['benign_all']['false_escalation_episodes']}",
            f"{new_res['benign_pre']['mean']:.4f}",
            f"{new_res['benign_pre']['median']:.4f}",
            f"{new_res['attack_b4']['mean']:.4f}",
            f"{new_res['attack_b4']['median']:.4f}",
            f"{new_res['attack_all_4_blocks']['mean']:.4f}",
            f"{new_res['attack_all_4_blocks']['median']:.4f}",
            f"{new_res['comparisons']['b4_vs_benign_all']['observed_mean_diff']:+.4f}",
            f"[{new_res['comparisons']['b4_vs_benign_all']['mean_diff_95ci'][0]:+.4f}, {new_res['comparisons']['b4_vs_benign_all']['mean_diff_95ci'][1]:+.4f}]",
            f"{new_res['comparisons']['b4_vs_benign_all']['overlap_coefficient']:.4f}",
            f"{new_res['comparisons']['b4_vs_benign_all']['cohens_d']:.4f}",
            f"{new_res['comparisons']['b4_vs_benign_pre']['observed_mean_diff']:+.4f}",
            f"[{new_res['comparisons']['b4_vs_benign_pre']['mean_diff_95ci'][0]:+.4f}, {new_res['comparisons']['b4_vs_benign_pre']['mean_diff_95ci'][1]:+.4f}]",
            f"{new_res['comparisons']['b4_vs_benign_pre']['overlap_coefficient']:.4f}",
            f"{new_res['comparisons']['b4_vs_benign_pre']['cohens_d']:.4f}",
            f"{new_res['comparisons']['all_blocks_vs_benign_all']['cohens_d']:.4f}",
            f"{new_res['comparisons']['all_blocks_vs_benign_all']['overlap_coefficient']:.4f}",
            f"{exp_d_results['NEW_ROLLING']['trust_drop_confirmed']}",
            f"{exp_d_results['NEW_ROLLING']['reversal_reduction_pct']:.1f}%",
        ],
    }
    results["summary_table"] = summary_table

    # 6. Save Artifacts & High-Resolution Comparative Plot
    out_dir = Path("artifacts/experiments/bridge_ab_experiment_v1")
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "manifest.json", "w") as f:
        json.dump(results, f, indent=2)

    fig, axes = plt.subplots(2, 2, figsize=(14, 10), dpi=300)

    # Subplot 1: Distribution of Risk Scores (Benign vs Attack B4)
    ax1 = axes[0, 0]
    bins = np.linspace(0, 1, 30)
    ax1.hist(benign_all_r0, bins=bins, alpha=0.45, density=True, color="#3B82F6", label="Benign All (N=1339)")
    ax1.hist(b4_r0, bins=bins, alpha=0.45, density=True, color="#EF4444", label="Attack Block 4 (N=343)")
    ax1.set_title("NEW (Rolling Bridge): Risk Distribution Density", fontsize=11, fontweight="bold")
    ax1.set_xlabel("Future Security Risk Score R(t)", fontsize=9)
    ax1.set_ylabel("Probability Density", fontsize=9)
    ax1.grid(True, linestyle="--", alpha=0.4)
    ax1.legend(loc="upper right", fontsize=8)

    # Subplot 2: Per-Block Cohen's d Comparison
    ax2 = axes[0, 1]
    block_names = [b_meta["block_id"] for b_meta in OBSERVED_INFILTRATION_BLOCKS]
    labels = ["Wed B1", "Wed B2", "Thu B3", "Thu B4"]
    old_ds = [old_res["individual_blocks"][bid]["cohens_d_vs_benign_all"] for bid in block_names]
    new_ds = [new_res["individual_blocks"][bid]["cohens_d_vs_benign_all"] for bid in block_names]
    x = np.arange(len(labels))
    width = 0.35
    ax2.bar(x - width/2, old_ds, width, label="OLD Static Bridge", color="#94A3B8", edgecolor="#475569")
    ax2.bar(x + width/2, new_ds, width, label="NEW Rolling Bridge", color="#10B981", edgecolor="#047857")
    ax2.set_title("Per-Block Effect Size (Cohen's d vs Benign Baseline)", fontsize=11, fontweight="bold")
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontsize=9)
    ax2.set_ylabel("Cohen's d", fontsize=9)
    ax2.grid(True, linestyle="--", alpha=0.4)
    ax2.legend(loc="upper left", fontsize=8)

    # Subplot 3: Per-Block Distribution Overlap
    ax3 = axes[1, 0]
    old_ovs = [old_res["individual_blocks"][bid]["overlap_vs_benign_all"] * 100 for bid in block_names]
    new_ovs = [new_res["individual_blocks"][bid]["overlap_vs_benign_all"] * 100 for bid in block_names]
    ax3.bar(x - width/2, old_ovs, width, label="OLD Static Bridge", color="#F87171", edgecolor="#B91C1C")
    ax3.bar(x + width/2, new_ovs, width, label="NEW Rolling Bridge", color="#38BDF8", edgecolor="#0284C7")
    ax3.set_title("Per-Block Distribution Overlap % (Lower is Better)", fontsize=11, fontweight="bold")
    ax3.set_xticks(x)
    ax3.set_xticklabels(labels, fontsize=9)
    ax3.set_ylabel("Overlap Coefficient (%)", fontsize=9)
    ax3.set_ylim(0, 100)
    ax3.grid(True, linestyle="--", alpha=0.4)
    ax3.legend(loc="upper right", fontsize=8)

    # Subplot 4: Experiment D Contradiction Dynamics
    ax4 = axes[1, 1]
    steps = np.arange(len(exp_d_results["OLD_STATIC"]["r0_trajectory"]))
    ax4.plot(steps, exp_d_results["OLD_STATIC"]["r0_trajectory"], label="OLD Static R(t)", color="#64748B", linewidth=2.0)
    ax4.plot(steps, exp_d_results["NEW_ROLLING"]["r0_trajectory"], label="NEW Rolling R(t)", color="#2563EB", linewidth=2.0)
    ax4.plot(steps, exp_d_results["NEW_ROLLING"]["trust_trajectory"], label="Composite Trust", color="#D97706", linestyle="--", linewidth=1.5)
    ax4.axvspan(6, 8, alpha=0.15, color="red", label="Escalation Phase")
    ax4.axvspan(9, 11, alpha=0.15, color="blue", label="Contradiction Phase")
    ax4.set_title("Experiment D: Contradiction Reversal & Dampening", fontsize=11, fontweight="bold")
    ax4.set_xlabel("Scenario Step Index", fontsize=9)
    ax4.set_ylabel("Score", fontsize=9)
    ax4.set_ylim(-0.02, 1.02)
    ax4.grid(True, linestyle="--", alpha=0.4)
    ax4.legend(loc="upper right", fontsize=8)

    fig.suptitle("BehavioralSecurityBridge A/B Experiment: Static vs Dynamic Rolling-Baseline", fontsize=13, fontweight="bold", y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plot_path = out_dir / "bridge_ab_comparison.png"
    plt.savefig(plot_path, dpi=300)
    plt.close()
    print(f"  Comparison plot saved to: {plot_path}")

    # 7. Print Output Table
    print("\n" + "=" * 80)
    print("A/B EXPERIMENT RESULTS SUMMARY TABLE")
    print("=" * 80)
    header = f"{'Metric':<46} | {'OLD_STATIC':<16} | {'NEW_ROLLING':<16}"
    print(header)
    print("-" * len(header))
    for m, o, n in zip(summary_table["Metric"], summary_table["OLD_STATIC"], summary_table["NEW_ROLLING"]):
        print(f"{m:<46} | {o:<16} | {n:<16}")
    print("=" * 80)

    # Per block comparison table
    print("\nPER-BLOCK EVALUATION BREAKDOWN (ALL 4 INFILTRATION BLOCKS):")
    print(f"{'Block ID':<10} | {'Name':<24} | {'N':<5} | {'OLD Mean':<9} | {'NEW Mean':<9} | {'OLD d':<7} | {'NEW d':<7} | {'OLD Overlap':<11} | {'NEW Overlap':<11}")
    print("-" * 110)
    for b_meta in OBSERVED_INFILTRATION_BLOCKS:
        bid = b_meta["block_id"]
        b_old = old_res["individual_blocks"][bid]
        b_new = new_res["individual_blocks"][bid]
        print(f"{bid:<10} | {b_old['name']:<24} | {b_old['window_count']:<5} | {b_old['stats']['mean']:<9.4f} | {b_new['stats']['mean']:<9.4f} | {b_old['cohens_d_vs_benign_all']:<+7.3f} | {b_new['cohens_d_vs_benign_all']:<+7.3f} | {b_old['overlap_vs_benign_all']:<11.3f} | {b_new['overlap_vs_benign_all']:<11.3f}")
    print("=" * 110)

    return results


if __name__ == "__main__":
    run_ab_experiment()
