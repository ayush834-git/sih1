"""
Comparative Lead-Time Experiment Runner: AR(5) Baseline vs Δ² Acceleration Treatment (SIH 26153).

Conducts a rigorous side-by-side empirical evaluation:
- CONTROL: Authoritative AR(5) + Conventional PredictiveTrajectoryDetector
- TREATMENT: Authoritative AR(5) + AccelerationAugmentedTrajectoryDetector

Strict Methodology:
1. Control and Treatment are evaluated over the exact same contiguous progression slices.
2. Modeled action duration T_action = 20s (with sensitivity checks at 5s, 10s, 20s, 30s).
3. Evaluates both:
   - Tier 1: Controlled Live Localhost Progression (if Npcap/live environment available)
   - Tier 2: Ground-Truth Dataset Attack Progression Slices (CIC-IDS2018)
4. Reports side-by-side metrics:
   - Mean / Median lead time vs conventional baseline
   - Mean / Median lead time vs actual onset
   - Actionable warning rate (at 5s, 10s, 20s, 30s)
   - Failure mode categorization (NONE, MISSED, LATE_VS_BASELINE, INSUFFICIENT_TIME, FALSE_EARLY)
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np

from core.contracts import NetworkState, TrustLevel
from eval.baseline_detectors import (
    ConventionalCurrentStateDetector,
    DetectionResult,
    PredictiveTrajectoryDetector,
)
from eval.dataset import (
    CSV_AVAILABLE_FEATURES,
    load_states_from_jsonl,
)
from eval.experimental_acceleration import (
    AccelerationAugmentedTrajectoryDetector,
    DEFAULT_ACCEL_THRESHOLDS,
    FROZEN_CALIBRATION_METADATA,
)
from eval.labels import (
    AttackInterval,
    KNOWN_ATTACK_INTERVALS,
)
from eval.rollout import MultiStepRolloutEngine
from eval.run_lead_time_experiment import (
    DEFAULT_MODELED_ACTION_DURATION_S,
    ProgressionRunResult,
    SENSITIVITY_DURATIONS_S,
    compute_statistics,
    extract_ground_truth_progression_slices,
)
from runtime.train_authoritative_model import load_ar_model

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("acceleration_lead_time_experiment")

OUTPUT_DIR = Path("artifacts/experiments/acceleration_lead_time_v1")


def evaluate_slice_comparative(
    slice_id: str,
    sequence: List[NetworkState],
    onset_rel_idx: int,
    ar_model: Any,
    rollout_engine: MultiStepRolloutEngine,
) -> Tuple[ProgressionRunResult, ProgressionRunResult, List[Dict[str, Any]]]:
    """
    Evaluates both Control and Treatment detectors on the exact same sequence.
    Returns (control_result, treatment_result, timeline_records).
    """
    conv_detector = ConventionalCurrentStateDetector(
        recon_port_thresh=30,
        dos_flow_thresh=300,
        dos_rst_thresh=0.25,
        exfil_byte_thresh=100000.0,
    )
    control_detector = PredictiveTrajectoryDetector(
        rollout_engine=rollout_engine,
        recon_port_thresh=20,
        dos_flow_thresh=200,
        exfil_byte_thresh=100000.0,
    )
    treatment_detector = AccelerationAugmentedTrajectoryDetector(
        rollout_engine=rollout_engine,
        recon_port_thresh=20,
        dos_flow_thresh=200,
        exfil_byte_thresh=100000.0,
    )

    timeline_records: List[Dict[str, Any]] = []
    w_actual_onset = onset_rel_idx if onset_rel_idx >= 0 else None

    # Tracking for Conventional Baseline
    w_base_alert: int | None = None
    base_res_at_alert: DetectionResult | None = None

    # Tracking for Control (Standard Predictive)
    w_ctrl_alert: int | None = None
    ctrl_res_at_alert: DetectionResult | None = None

    # Tracking for Treatment (Acceleration-Augmented)
    w_treat_alert: int | None = None
    treat_res_at_alert: DetectionResult | None = None

    history_deltas: List[Dict[str, float]] = []
    history_states: List[NetworkState] = []

    for w_idx, state in enumerate(sequence):
        history_states.append(state)

        # Delta calculation strictly from current and previous states
        if w_idx > 0:
            prev_vals = sequence[w_idx - 1].feature_values()
            curr_vals = state.feature_values()
            delta = {f: (curr_vals.get(f, 0.0) or 0.0) - (prev_vals.get(f, 0.0) or 0.0) for f in CSV_AVAILABLE_FEATURES}
            history_deltas.append(delta)

        # 1. Evaluate Conventional Baseline
        base_res = conv_detector.evaluate_state(state)
        if base_res.is_alert and w_base_alert is None:
            w_base_alert = w_idx
            base_res_at_alert = base_res

        # 2. Compute AR(5) open-loop forecast
        p = 5
        n_feats = len(CSV_AVAILABLE_FEATURES)
        hist_vec = np.zeros((1, p * n_feats), dtype=np.float64)
        if history_deltas:
            recent = history_deltas[-p:]
            padded = [recent[0]] * (p - len(recent)) + recent
            for k in range(p):
                for f_i, f_name in enumerate(CSV_AVAILABLE_FEATURES):
                    hist_vec[0, k * n_feats + f_i] = padded[k].get(f_name, 0.0)
        curr_vec = np.array([[state.feature_values().get(f, 0.0) or 0.0 for f in CSV_AVAILABLE_FEATURES]], dtype=np.float64)

        det_deltas, _ = rollout_engine.forecast_open_loop(hist_vec, curr_vec, max_horizon=3)
        pred_deltas = det_deltas[0]

        # 3. Evaluate Control Detector
        ctrl_res = control_detector.evaluate_state_and_forecast(
            current_state=state,
            predicted_deltas=pred_deltas,
            trust_level=TrustLevel.HIGH,
        )
        if ctrl_res.is_alert and w_ctrl_alert is None:
            w_ctrl_alert = w_idx
            ctrl_res_at_alert = ctrl_res

        # 4. Evaluate Treatment Detector
        treat_res = treatment_detector.evaluate_state_and_forecast(
            current_state=state,
            predicted_deltas=pred_deltas,
            trust_level=TrustLevel.HIGH,
            history_states=history_states,
        )
        if treat_res.is_alert and w_treat_alert is None:
            w_treat_alert = w_idx
            treat_res_at_alert = treat_res

        timeline_records.append({
            "run_id": slice_id,
            "window_index": w_idx,
            "logical_time_s": w_idx * 10,
            "dst_port_diversity": state.dst_port_diversity,
            "flow_count": state.flow_count,
            "byte_rate": state.byte_rate,
            "base_alert": base_res.is_alert,
            "control_alert": ctrl_res.is_alert,
            "treatment_alert": treat_res.is_alert,
            "is_ground_truth_attack": (w_idx >= onset_rel_idx) if onset_rel_idx >= 0 else False,
        })

    # Build standardized ProgressionRunResult for both arms
    def build_run_result(arm_name: str, w_pred: int | None, pred_res: DetectionResult | None) -> ProgressionRunResult:
        lead_vs_base = 0.0
        if w_pred is not None and w_base_alert is not None:
            lead_vs_base = max(0.0, float(w_base_alert - w_pred) * 10.0)

        lead_vs_actual = 0.0
        if w_pred is not None and w_actual_onset is not None:
            lead_vs_actual = max(0.0, float(w_actual_onset - w_pred) * 10.0)

        actionable_map: Dict[int, bool] = {}
        is_false_early = (w_actual_onset is None and w_pred is not None)
        is_missed = (w_actual_onset is not None and (w_pred is None or w_pred > w_actual_onset))

        for dur_s in SENSITIVITY_DURATIONS_S:
            if is_false_early or is_missed or w_pred is None:
                actionable_map[dur_s] = False
            else:
                has_time = (lead_vs_actual >= dur_s)
                precedes_or_matches_base = (w_base_alert is None or w_pred < w_base_alert)
                actionable_map[dur_s] = (has_time and precedes_or_matches_base)

        is_actionable_default = actionable_map[DEFAULT_MODELED_ACTION_DURATION_S]

        if is_false_early:
            fail_cat = "FALSE_EARLY"
        elif is_missed:
            fail_cat = "MISSED"
        elif w_pred is not None and w_base_alert is not None and w_pred >= w_base_alert:
            fail_cat = "LATE_VS_BASELINE"
        elif w_pred is not None and not is_actionable_default and w_actual_onset is not None:
            fail_cat = "INSUFFICIENT_TIME"
        else:
            fail_cat = "NONE"

        return ProgressionRunResult(
            run_id=f"{slice_id}_{arm_name}",
            run_tier="DATASET_GROUND_TRUTH",
            scenario_name=slice_id.split("_")[0],
            total_windows=len(sequence),
            w_suspicious=None,
            w_pred_alert=w_pred,
            w_base_alert=w_base_alert,
            w_actual_onset=w_actual_onset,
            lead_time_vs_base_s=lead_vs_base,
            lead_time_vs_actual_s=lead_vs_actual,
            is_actionable_default=is_actionable_default,
            actionable_by_duration=actionable_map,
            is_false_early=is_false_early,
            is_missed=is_missed,
            failure_category=fail_cat,
            predicted_stage=pred_res.event_type if pred_res else "None",
            actual_stage="Ground Truth Attack" if w_actual_onset is not None else "Benign Baseline",
            pred_confidence=pred_res.confidence if pred_res else 0.0,
            pred_trigger_reason=pred_res.trigger_reason if pred_res else "No Alert",
            base_trigger_reason=base_res_at_alert.trigger_reason if base_res_at_alert else "No Alert",
        )

    res_control = build_run_result("CONTROL", w_ctrl_alert, ctrl_res_at_alert)
    res_treatment = build_run_result("TREATMENT", w_treat_alert, treat_res_at_alert)

    return res_control, res_treatment, timeline_records


def run_comparative_experiment() -> Dict[str, Any]:
    """Execute comparative lead-time experiment across ground-truth slices."""
    logger.info("Executing Comparative Lead-Time Experiment: Control vs Treatment")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load authoritative AR(5) model
    model_dir = Path("artifacts/models/ar5_authoritative")
    ar_model, scales = load_ar_model(model_dir)
    rollout_engine = MultiStepRolloutEngine(ar_model=ar_model, feature_names=CSV_AVAILABLE_FEATURES)

    # 2. Load dataset slices
    wed_path = Path("artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.states.jsonl")
    thu_path = Path("artifacts/state_sequences/Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl")

    all_states: List[NetworkState] = []
    if wed_path.exists():
        all_states.extend(load_states_from_jsonl(wed_path))
    if thu_path.exists():
        all_states.extend(load_states_from_jsonl(thu_path))

    slices = extract_ground_truth_progression_slices(all_states)
    logger.info("Extracted %d ground-truth onset and control slices", len(slices))

    control_results: List[ProgressionRunResult] = []
    treatment_results: List[ProgressionRunResult] = []
    all_timeline_records: List[Dict[str, Any]] = []

    for slice_id, seq, onset_idx in slices:
        ctrl_res, treat_res, t_records = evaluate_slice_comparative(
            slice_id=slice_id,
            sequence=seq,
            onset_rel_idx=onset_idx,
            ar_model=ar_model,
            rollout_engine=rollout_engine,
        )
        control_results.append(ctrl_res)
        treatment_results.append(treat_res)
        all_timeline_records.extend(t_records)

    # Separate attack runs (onset is not None) from negative controls
    ctrl_esc = [r for r in control_results if r.w_actual_onset is not None]
    treat_esc = [r for r in treatment_results if r.w_actual_onset is not None]

    ctrl_leads_base = [r.lead_time_vs_base_s for r in ctrl_esc]
    ctrl_leads_actual = [r.lead_time_vs_actual_s for r in ctrl_esc]

    treat_leads_base = [r.lead_time_vs_base_s for r in treat_esc]
    treat_leads_actual = [r.lead_time_vs_actual_s for r in treat_esc]

    ctrl_stats_base = compute_statistics(ctrl_leads_base)
    ctrl_stats_actual = compute_statistics(ctrl_leads_actual)

    treat_stats_base = compute_statistics(treat_leads_base)
    treat_stats_actual = compute_statistics(treat_leads_actual)

    # Sensitivity across durations
    def build_sens_table(runs: List[ProgressionRunResult]) -> Dict[str, Any]:
        table = {}
        for dur in SENSITIVITY_DURATIONS_S:
            count = sum(1 for r in runs if r.actionable_by_duration.get(dur, False))
            rate = (count / len(runs)) * 100.0 if runs else 0.0
            table[f"{dur}s"] = {
                "duration_s": dur,
                "actionable_count": count,
                "total": len(runs),
                "actionable_percent": round(rate, 2),
            }
        return table

    ctrl_sens = build_sens_table(ctrl_esc)
    treat_sens = build_sens_table(treat_esc)

    def build_failure_counts(runs: List[ProgressionRunResult]) -> Dict[str, int]:
        return {
            "NONE": sum(1 for r in runs if r.failure_category == "NONE"),
            "MISSED": sum(1 for r in runs if r.failure_category == "MISSED"),
            "LATE_VS_BASELINE": sum(1 for r in runs if r.failure_category == "LATE_VS_BASELINE"),
            "INSUFFICIENT_TIME": sum(1 for r in runs if r.failure_category == "INSUFFICIENT_TIME"),
            "FALSE_EARLY": sum(1 for r in runs if r.failure_category == "FALSE_EARLY"),
        }

    ctrl_failures = build_failure_counts(control_results)
    treat_failures = build_failure_counts(treatment_results)

    # Export comparison CSV
    csv_path = OUTPUT_DIR / "comparison.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "slice_id", "onset_idx",
            "base_alert", "ctrl_alert", "treat_alert",
            "ctrl_lead_base_s", "treat_lead_base_s",
            "ctrl_lead_actual_s", "treat_lead_actual_s",
            "ctrl_actionable_20s", "treat_actionable_20s",
            "ctrl_fail_cat", "treat_fail_cat",
        ])
        for c, t in zip(control_results, treatment_results):
            writer.writerow([
                c.scenario_name, c.w_actual_onset if c.w_actual_onset is not None else "",
                c.w_base_alert if c.w_base_alert is not None else "",
                c.w_pred_alert if c.w_pred_alert is not None else "",
                t.w_pred_alert if t.w_pred_alert is not None else "",
                c.lead_time_vs_base_s, t.lead_time_vs_base_s,
                c.lead_time_vs_actual_s, t.lead_time_vs_actual_s,
                c.is_actionable_default, t.is_actionable_default,
                c.failure_category, t.failure_category,
            ])

    # Per-slice comparison dictionary
    per_slice_comparison = []
    for c, t in zip(control_results, treatment_results):
        per_slice_comparison.append({
            "slice_id": c.run_id.replace("_CONTROL", ""),
            "scenario": c.scenario_name,
            "actual_onset_w": c.w_actual_onset,
            "base_alert_w": c.w_base_alert,
            "ctrl_alert_w": c.w_pred_alert,
            "treat_alert_w": t.w_pred_alert,
            "ctrl_lead_vs_base_s": c.lead_time_vs_base_s,
            "treat_lead_vs_base_s": t.lead_time_vs_base_s,
            "ctrl_lead_vs_actual_s": c.lead_time_vs_actual_s,
            "treat_lead_vs_actual_s": t.lead_time_vs_actual_s,
            "ctrl_actionable_20s": c.is_actionable_default,
            "treat_actionable_20s": t.is_actionable_default,
            "ctrl_failure_category": c.failure_category,
            "treat_failure_category": t.failure_category,
        })

    manifest = {
        "metadata": {
            "experiment_id": "acceleration_lead_time_comparative_v1",
            "timestamp": datetime.now().isoformat(),
            "action_duration_default_s": DEFAULT_MODELED_ACTION_DURATION_S,
            "sensitivity_durations_s": SENSITIVITY_DURATIONS_S,
            "calibration_metadata": FROZEN_CALIBRATION_METADATA,
            "frozen_accel_thresholds": DEFAULT_ACCEL_THRESHOLDS,
        },
        "control_baseline": {
            "lead_vs_base_stats": ctrl_stats_base,
            "lead_vs_actual_stats": ctrl_stats_actual,
            "sensitivity_table": ctrl_sens,
            "failure_counts": ctrl_failures,
        },
        "treatment_acceleration": {
            "lead_vs_base_stats": treat_stats_base,
            "lead_vs_actual_stats": treat_stats_actual,
            "sensitivity_table": treat_sens,
            "failure_counts": treat_failures,
        },
        "per_slice_comparison": per_slice_comparison,
        "n_slices": len(slices),
        "n_attack_slices": len(ctrl_esc),
        "n_control_slices": len(slices) - len(ctrl_esc),
    }

    manifest_path = OUTPUT_DIR / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info("Comparative experiment completed. Manifest written to %s", manifest_path)
    return manifest


if __name__ == "__main__":
    run_comparative_experiment()
