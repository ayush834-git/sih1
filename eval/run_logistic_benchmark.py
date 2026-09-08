"""Strict Problem Statement (PS 26153) Benchmark: Logistic Regression vs Temporal Model.

Compares static Logistic Regression against the temporal AR(5) dynamics model on:
- Exactly the same dataset (CSE-CIC-IDS2018 Wednesday-28 and Thursday-01)
- Exactly the same 15 features (CSV_AVAILABLE_FEATURES)
- Exactly the same chronological 60/15/25 split
- Methodology Guard 1: Transition count and split sizes are dynamically computed from data.
- Methodology Guard 2: Held-out test set is NEVER touched during model fitting or calibration.
- Full metrics: Precision, Recall, F1, False Positive Rate (FPR), and Advance Lead Time.
"""
from __future__ import annotations

import csv
import hashlib
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

from core.contracts import STATE_SCHEMA_HASH, TrustLevel
from eval.baseline_detectors import (
    ConventionalCurrentStateDetector,
    PredictiveTrajectoryDetector,
)
from eval.dataset import (
    CSV_AVAILABLE_FEATURES,
    DatasetArrays,
    TransitionSample,
    chronological_split,
    extract_transitions,
    load_states_from_jsonl,
    samples_to_arrays,
)
from eval.labels import (
    TRANSITION_ATTACK_ONSET,
    annotate_transitions,
)
from eval.metrics_v2 import compute_training_scales
from eval.models_v2 import ARStyleBaselineV2
from eval.progression_probability import ProgressionProbabilityModel
from eval.rollout import MultiStepRolloutEngine


def compute_binary_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    model_name: str,
) -> Dict[str, Any]:
    """Compute comprehensive classification metrics including FPR and confusion matrix."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    
    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    accuracy = float((tp + tn) / (tp + tn + fp + fn))

    return {
        "model_name": model_name,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round(accuracy, 4),
        "total_test_samples": int(len(y_true)),
        "attack_prevalence": round(float(np.mean(y_true)), 4),
    }


def run_benchmark(
    wed_states_path: str | Path = "artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.states.jsonl",
    thu_states_path: str | Path = "artifacts/state_sequences/Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl",
    output_dir: str | Path = "artifacts/experiments/logistic_regression_benchmark_v1",
) -> Dict[str, Any]:
    """Execute the strict PS 26153 Logistic Regression comparative benchmark."""
    start_time = time.time()
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("SIH PS 26153 — STRICT BENCHMARK: LOGISTIC REGRESSION vs TEMPORAL MODEL")
    print("=" * 80)

    # 1. Load data
    print("\n[1/6] Loading canonical state sequences...")
    wed_states = load_states_from_jsonl(wed_states_path)
    thu_states = load_states_from_jsonl(thu_states_path)
    all_states = wed_states + thu_states
    print(f"  Wednesday States: {len(wed_states)} | Thursday States: {len(thu_states)} | Total: {len(all_states)}")

    # 2. Extract transitions dynamically (Methodology Guard 1)
    print("\n[2/6] Extracting contiguous transitions (history_depth=6 for AR(5))...")
    transitions, dropped = extract_transitions(
        all_states,
        history_depth=6,
        feature_names=CSV_AVAILABLE_FEATURES,
    )
    total_transitions = len(transitions)
    print(f"  Total Valid Contiguous Transitions: {total_transitions}")
    print(f"  Dropped reason breakdown: {dropped}")

    # 3. Label transitions using dataset ground truth
    print("\n[3/6] Deriving supervised attack progression labels...")
    labeled_transitions = annotate_transitions(transitions)
    total_labeled = len(labeled_transitions)
    assert total_labeled == total_transitions, "Mismatch between transitions and labels"

    # Count attack vs benign transitions
    curr_attack_cnt = sum(lt.current_is_attack for lt in labeled_transitions)
    next_attack_cnt = sum(lt.next_is_attack for lt in labeled_transitions)
    onset_cnt = sum(1 for lt in labeled_transitions if lt.transition_type == TRANSITION_ATTACK_ONSET)
    print(f"  Current Attack Transitions: {curr_attack_cnt} / {total_transitions} ({curr_attack_cnt/total_transitions*100:.1f}%)")
    print(f"  Lookahead Attack (h=1) Transitions: {next_attack_cnt} / {total_transitions} ({next_attack_cnt/total_transitions*100:.1f}%)")
    print(f"  Exact Attack Onsets (0 -> 1): {onset_cnt}")

    # 4. Strict Chronological Split (Methodology Guard 1 & 2)
    print("\n[4/6] Performing strict chronological 60/15/25 split...")
    sorted_labeled = sorted(labeled_transitions, key=lambda lt: lt.sample.target_start)
    
    n_total = len(sorted_labeled)
    n_train = int(round(n_total * 0.60))
    n_val = int(round(n_total * 0.15))
    n_test = n_total - n_train - n_val

    train_lt = sorted_labeled[:n_train]
    val_lt = sorted_labeled[n_train : n_train + n_val]
    test_lt = sorted_labeled[n_train + n_val :]

    print(f"  Exact Split Sizes: Train={len(train_lt)} ({len(train_lt)/n_total*100:.1f}%), Val={len(val_lt)} ({len(val_lt)/n_total*100:.1f}%), Test={len(test_lt)} ({len(test_lt)/n_total*100:.1f}%)")
    print(f"  Chronological Boundaries:")
    print(f"    Train: {train_lt[0].sample.target_start.isoformat()} -> {train_lt[-1].sample.target_start.isoformat()}")
    print(f"    Val:   {val_lt[0].sample.target_start.isoformat()} -> {val_lt[-1].sample.target_start.isoformat()}")
    print(f"    Test:  {test_lt[0].sample.target_start.isoformat()} -> {test_lt[-1].sample.target_start.isoformat()}")

    # Extract raw arrays
    train_samples = [lt.sample for lt in train_lt]
    val_samples = [lt.sample for lt in val_lt]
    test_samples = [lt.sample for lt in test_lt]

    arr_tr = samples_to_arrays(train_samples)
    arr_va = samples_to_arrays(val_samples)
    arr_te = samples_to_arrays(test_samples)

    # Features: S_t (current state)
    X_train_curr = arr_tr.current_states
    X_val_curr = arr_va.current_states
    X_test_curr = arr_te.current_states

    # Targets:
    # Target A: Current Attack State (t)
    y_train_curr = np.array([lt.current_is_attack for lt in train_lt])
    y_val_curr = np.array([lt.current_is_attack for lt in val_lt])
    y_test_curr = np.array([lt.current_is_attack for lt in test_lt])

    # Target B: Forward Progression Lookahead within h=3 (30s)
    y_train_prog = np.array([lt.lookahead_attack_h3 for lt in train_lt])
    y_val_prog = np.array([lt.lookahead_attack_h3 for lt in val_lt])
    y_test_prog = np.array([lt.lookahead_attack_h3 for lt in test_lt])

    # 5. Fit Models Strictly on Train / Val (Test Set is Reserved for Evaluation)
    print("\n[5/6] Training benchmark models on identical split...")
    
    # 5a. Train AR(5) Temporal Dynamics Model
    train_scales = compute_training_scales(arr_tr.y, CSV_AVAILABLE_FEATURES)
    ar5_model = ARStyleBaselineV2(fixed_p=5)
    ar5_model.fit(
        arr_tr.X, arr_tr.y, arr_tr.X_deltas,
        arr_va.X, arr_va.y, arr_va.X_deltas,
        scales=train_scales,
    )
    rollout_engine = MultiStepRolloutEngine(ar5_model, CSV_AVAILABLE_FEATURES)

    # 5b. Model 1: Static Logistic Regression (Current State Classifier)
    scaler_static = StandardScaler()
    X_tr_curr_scaled = scaler_static.fit_transform(X_train_curr)
    X_va_curr_scaled = scaler_static.transform(X_val_curr)
    X_te_curr_scaled = scaler_static.transform(X_test_curr)

    lr_static_current = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
    lr_static_current.fit(X_tr_curr_scaled, y_train_curr)

    # 5c. Model 2: Static Logistic Regression (Anticipatory / Forward Lookahead h=3)
    lr_static_forecast = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
    lr_static_forecast.fit(X_tr_curr_scaled, y_train_prog)

    # 5d. Model 3: Conventional Current-State Threshold Detector
    current_detector = ConventionalCurrentStateDetector(
        recon_port_thresh=20,
        dos_flow_thresh=200,
        dos_rst_thresh=0.25,
        exfil_byte_thresh=100000.0,
    )

    # 5e. Model 4: AR(5) Multi-Step Predictive Trajectory Detector
    pred_detector = PredictiveTrajectoryDetector(
        rollout_engine=rollout_engine,
        feature_names=CSV_AVAILABLE_FEATURES,
        recon_port_thresh=20,
        dos_flow_thresh=200,
        exfil_byte_thresh=100000.0,
    )

    # 5f. Model 5: Calibrated Progression Probability Classifier (Methodology Guard 2)
    # Temporal feature: [Current S_t, mean of AR(5) forecasted deltas]
    # Forecast delta features on train, val, test
    n_feats = len(CSV_AVAILABLE_FEATURES)
    preds_delta_tr = ar5_model.predict(arr_tr.X, arr_tr.X_deltas, n_features=n_feats)
    preds_delta_va = ar5_model.predict(arr_va.X, arr_va.X_deltas, n_features=n_feats)
    preds_delta_te = ar5_model.predict(arr_te.X, arr_te.X_deltas, n_features=n_feats)

    # Combined representation: [S_t, \Delta \hat{S}_{t+1}]
    X_tr_temporal = np.hstack([X_train_curr, preds_delta_tr])
    X_va_temporal = np.hstack([X_val_curr, preds_delta_va])
    X_te_temporal = np.hstack([X_test_curr, preds_delta_te])

    calibrated_prog_model = ProgressionProbabilityModel(
        feature_names=CSV_AVAILABLE_FEATURES,
        horizon_steps=3,
        calibration_method="sigmoid",
    )
    # Fit strictly on train and calibrate on val
    calibrated_prog_model.fit(
        X_train=X_tr_temporal,
        y_train=y_train_prog,
        X_val=X_va_temporal,
        y_val=y_val_prog,
    )

    # 6. Evaluate all models on the HELD-OUT TEST SPLIT
    print("\n[6/6] Evaluating all models on the held-out test split...")
    
    # 1. Static LR (Current State)
    preds_lr_curr = lr_static_current.predict(X_te_curr_scaled)
    m_lr_curr = compute_binary_metrics(y_test_curr, preds_lr_curr, "1_LogisticRegression_CurrentState")

    # 2. Static LR (Anticipatory Lookahead h=3)
    preds_lr_fore = lr_static_forecast.predict(X_te_curr_scaled)
    m_lr_fore = compute_binary_metrics(y_test_prog, preds_lr_fore, "2_LogisticRegression_AnticipatoryStatic")

    # 3. Conventional Current-State Threshold Detector
    # Evaluate each test sample state
    preds_base_curr = []
    for lt in test_lt:
        vals = lt.sample.current_state
        port_div = vals.get("dst_port_diversity", 0.0)
        flow_cnt = vals.get("flow_count", 0.0)
        rst_ratio = vals.get("rst_ratio", 0.0)
        byte_rate = vals.get("byte_rate", 0.0)
        is_alert = (
            port_div >= 20 or
            (flow_cnt >= 200 and rst_ratio >= 0.25) or
            byte_rate >= 100000.0
        )
        preds_base_curr.append(1 if is_alert else 0)
    m_base_curr = compute_binary_metrics(y_test_curr, np.array(preds_base_curr), "3_Conventional_CurrentStateRule")

    # 4. Temporal AR(5) Predictive Trajectory Detector
    # Rollout multi-step deltas on test set and evaluate alert
    preds_pred_traj = []
    lead_times_pred = []
    lead_times_lr = []

    # Map onset test indices
    onset_test_indices = [idx for idx, lt in enumerate(test_lt) if lt.transition_type == TRANSITION_ATTACK_ONSET]

    for idx, lt in enumerate(test_lt):
        h_vec = arr_te.X_deltas[idx:idx+1, :]
        c_vec = arr_te.current_states[idx:idx+1, :]
        p_deltas, _ = rollout_engine.forecast_open_loop(h_vec, c_vec, max_horizon=3)
        
        # Squeeze to (3, n_feats)
        deltas_matrix = p_deltas[0, :, :]
        
        # Check projected threshold crossing
        vals = lt.sample.current_state
        port_idx = CSV_AVAILABLE_FEATURES.index("dst_port_diversity")
        flow_idx = CSV_AVAILABLE_FEATURES.index("flow_count")
        byte_idx = CSV_AVAILABLE_FEATURES.index("byte_rate")
        
        cur_port = vals.get("dst_port_diversity", 0.0)
        cur_flow = vals.get("flow_count", 0.0)
        cur_byte = vals.get("byte_rate", 0.0)

        cum_port = cur_port
        cum_flow = cur_flow
        cum_byte = cur_byte
        is_proj_alert = False

        for h in range(3):
            cum_port += deltas_matrix[h, port_idx]
            cum_flow += deltas_matrix[h, flow_idx]
            cum_byte += deltas_matrix[h, byte_idx]
            if cum_port >= 20 or cum_flow >= 200 or cum_byte >= 100000.0:
                is_proj_alert = True
                break

        # Fallback to current state alert if current state is already elevated
        if cur_port >= 20 or cur_flow >= 200 or cur_byte >= 100000.0:
            is_proj_alert = True

        preds_pred_traj.append(1 if is_proj_alert else 0)

    m_pred_traj = compute_binary_metrics(y_test_prog, np.array(preds_pred_traj), "4_Temporal_AR5_PredictiveTrajectory")

    # 5. Calibrated Progression Probability Classifier
    probs_calib_te = calibrated_prog_model.predict_proba(X_te_temporal)
    preds_calib_te = (probs_calib_te >= 0.50).astype(int)
    m_calib = compute_binary_metrics(y_test_prog, preds_calib_te, "5_Calibrated_Temporal_ProgressionProbability")
    calib_eval = calibrated_prog_model.evaluate_on_test(X_te_temporal, y_test_prog)

    # Lead Time Comparison on Test Set Onset Intervals
    lead_time_data: List[Dict[str, Any]] = []
    for onset_idx in onset_test_indices:
        onset_lt = test_lt[onset_idx]
        t_onset = onset_lt.sample.target_start

        # Check up to 3 windows (30s) prior to onset: did the model alert before onset?
        # Model 1: Static LR
        lr_alert_prior = False
        lr_alert_step = 0
        for prior_k in range(1, 4):
            if onset_idx - prior_k >= 0:
                if preds_lr_curr[onset_idx - prior_k] == 1:
                    lr_alert_prior = True
                    lr_alert_step = prior_k
                    break
        lead_time_lr_s = lr_alert_step * 10.0 if lr_alert_prior else 0.0

        # Model 4: Temporal AR(5)
        pred_alert_prior = False
        pred_alert_step = 0
        for prior_k in range(1, 4):
            if onset_idx - prior_k >= 0:
                if preds_pred_traj[onset_idx - prior_k] == 1:
                    pred_alert_prior = True
                    pred_alert_step = prior_k
                    break
        lead_time_pred_s = pred_alert_step * 10.0 if pred_alert_prior else 0.0

        lead_time_data.append({
            "onset_index_in_test": onset_idx,
            "target_timestamp": t_onset.isoformat(),
            "static_lr_lead_time_seconds": lead_time_lr_s,
            "temporal_ar5_lead_time_seconds": lead_time_pred_s,
            "lead_time_advantage_seconds": lead_time_pred_s - lead_time_lr_s,
        })

    avg_lead_time_lr = float(np.mean([d["static_lr_lead_time_seconds"] for d in lead_time_data])) if lead_time_data else 0.0
    avg_lead_time_pred = float(np.mean([d["temporal_ar5_lead_time_seconds"] for d in lead_time_data])) if lead_time_data else 0.0

    all_metrics = [m_lr_curr, m_lr_fore, m_base_curr, m_pred_traj, m_calib]

    # Print summary table
    print("\n" + "=" * 90)
    print(f"{'Model':<42} {'F1':>8} {'Precision':>10} {'Recall':>8} {'FPR':>8} {'Accuracy':>10}")
    print("-" * 90)
    for m in all_metrics:
        print(f"{m['model_name']:<42} {m['f1_score']:>8.4f} {m['precision']:>10.4f} {m['recall']:>8.4f} {m['false_positive_rate']:>8.4f} {m['accuracy']:>10.4f}")
    print("=" * 90)
    print(f"\nEmpirical Advance Lead Time Before Attack Manifestation:")
    print(f"  - Static Logistic Regression:     {avg_lead_time_lr:.1f} seconds")
    print(f"  - Temporal AR(5) Dynamics Model:  {avg_lead_time_pred:.1f} seconds (Gain: +{avg_lead_time_pred - avg_lead_time_lr:.1f}s)")
    print(f"\nCalibrated Probability Evaluation on Held-Out Test Split:")
    print(f"  - Brier Score (lower is better):  {calib_eval.brier_score:.4f}")
    print(f"  - Expected Calibration Error:    {calib_eval.expected_calibration_error:.4f}")
    print(f"  - Maximum Calibration Error:     {calib_eval.maximum_calibration_error:.4f}")
    print(f"  - ROC-AUC:                       {calib_eval.roc_auc:.4f}")

    # Persist artifacts
    # 1. benchmark_comparison.csv
    csv_path = out_dir / "benchmark_comparison.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_metrics[0].keys()))
        writer.writeheader()
        writer.writerows(all_metrics)

    # 2. benchmark_results.json
    results_json_path = out_dir / "benchmark_results.json"
    full_report = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "schema_hash": STATE_SCHEMA_HASH,
            "total_states": len(all_states),
            "total_transitions": total_transitions,
            "train_size": len(train_lt),
            "val_size": len(val_lt),
            "test_size": len(test_lt),
            "features_used": CSV_AVAILABLE_FEATURES,
        },
        "models_evaluated": all_metrics,
        "lead_time_analysis": {
            "average_lead_time_static_lr_seconds": round(avg_lead_time_lr, 2),
            "average_lead_time_temporal_ar5_seconds": round(avg_lead_time_pred, 2),
            "average_advantage_seconds": round(avg_lead_time_pred - avg_lead_time_lr, 2),
            "evaluated_onsets": lead_time_data,
        },
        "calibration_metrics": asdict(calib_eval),
    }
    with open(results_json_path, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    # 3. manifest.json
    manifest_path = out_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({
            "experiment_id": "logistic_regression_benchmark_v1",
            "runtime_seconds": round(time.time() - start_time, 2),
            "dataset_sources": [str(wed_states_path), str(thu_states_path)],
            "output_files": [str(csv_path), str(results_json_path)],
        }, f, indent=2)

    print(f"\nArtifacts successfully persisted to {out_dir}")
    return full_report


if __name__ == "__main__":
    run_benchmark()
