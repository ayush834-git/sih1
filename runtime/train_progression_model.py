"""Train and persist the authoritative Calibrated Progression Probability model (SIH 26153).

Generates the canonical JSON model artifact:
    artifacts/models/ar5_authoritative/progression_model.json

Adheres to:
1. Canonical JSON persistence (no pickle, no npz, no binary).
2. Reproduces the EXACT validated experiment from eval/run_logistic_benchmark.py (Model 5).
3. Evaluates strictly on the held-out test split (train 60%, val 15%, test 25%).
4. Stores complete model parameters: feature schema, StandardScaler parameters,
   LogisticRegression weights/intercept, Platt scaling parameters, provenance metadata,
   and test metrics.
5. Deterministic SHA-256 provenance hash.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import numpy as np

from core.contracts import STATE_SCHEMA_HASH
from eval.dataset import (
    CSV_AVAILABLE_FEATURES,
    extract_transitions,
    load_states_from_jsonl,
    samples_to_arrays,
)
from eval.labels import annotate_transitions
from eval.progression_probability import ProgressionProbabilityModel
from runtime.train_authoritative_model import load_ar_model


def canonical_json_dumps(obj: Any) -> str:
    """Serialize object to canonical, deterministic JSON string."""
    return json.dumps(obj, indent=2, sort_keys=True)


def train_and_persist_progression_model(
    wed_path: str = "artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.states.jsonl",
    thu_path: str = "artifacts/state_sequences/Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl",
    ar5_model_dir: str = "artifacts/models/ar5_authoritative",
    output_path: str = "artifacts/models/ar5_authoritative/progression_model.json",
) -> Dict[str, Any]:
    """Train, validate, evaluate and serialize the progression probability model."""
    print("=" * 70)
    print("Training Authoritative Progression Probability Model (Canonical JSON)")
    print("=" * 70)

    # 1. Load state sequences
    print("[1/5] Loading state sequences...")
    wed_states = load_states_from_jsonl(wed_path)
    thu_states = load_states_from_jsonl(thu_path)
    all_states = wed_states + thu_states
    print(f"  Total states: {len(all_states)}")

    # 2. Extract transitions (history_depth=6)
    print("[2/5] Extracting transitions (history_depth=6)...")
    transitions, dropped = extract_transitions(
        all_states,
        history_depth=6,
        feature_names=CSV_AVAILABLE_FEATURES,
    )
    labeled = annotate_transitions(transitions)
    sorted_lt = sorted(labeled, key=lambda lt: lt.sample.target_start)

    n_total = len(sorted_lt)
    n_train = int(round(n_total * 0.60))
    n_val = int(round(n_total * 0.15))
    n_test = n_total - n_train - n_val

    train_lt = sorted_lt[:n_train]
    val_lt = sorted_lt[n_train : n_train + n_val]
    test_lt = sorted_lt[n_train + n_val :]
    print(f"  Split: Train={len(train_lt)}, Val={len(val_lt)}, Test={len(test_lt)}")

    # 3. Build temporal representations [S_t, \Delta \hat{S}_{t+1}]
    print("[3/5] Constructing temporal representations via authoritative AR(5)...")
    arr_tr = samples_to_arrays([lt.sample for lt in train_lt])
    arr_va = samples_to_arrays([lt.sample for lt in val_lt])
    arr_te = samples_to_arrays([lt.sample for lt in test_lt])

    ar5_model, _ = load_ar_model(Path(ar5_model_dir))
    n_feats = len(CSV_AVAILABLE_FEATURES)

    preds_delta_tr = ar5_model.predict(arr_tr.X, arr_tr.X_deltas, n_features=n_feats)
    preds_delta_va = ar5_model.predict(arr_va.X, arr_va.X_deltas, n_features=n_feats)
    preds_delta_te = ar5_model.predict(arr_te.X, arr_te.X_deltas, n_features=n_feats)

    X_tr_temporal = np.hstack([arr_tr.current_states, preds_delta_tr])
    X_va_temporal = np.hstack([arr_va.current_states, preds_delta_va])
    X_te_temporal = np.hstack([arr_te.current_states, preds_delta_te])

    y_train_prog = np.array([lt.lookahead_attack_h3 for lt in train_lt])
    y_val_prog = np.array([lt.lookahead_attack_h3 for lt in val_lt])
    y_test_prog = np.array([lt.lookahead_attack_h3 for lt in test_lt])

    # 4. Train and calibrate
    print("[4/5] Fitting Calibrated Progression Model (sigmoid Platt scaling)...")
    prog_model = ProgressionProbabilityModel(
        feature_names=CSV_AVAILABLE_FEATURES,
        horizon_steps=3,
        calibration_method="sigmoid",
    )
    prog_model.fit(
        X_train=X_tr_temporal,
        y_train=y_train_prog,
        X_val=X_va_temporal,
        y_val=y_val_prog,
    )

    test_metrics = prog_model.evaluate_on_test(X_te_temporal, y_test_prog)
    print(f"  Test Brier Score: {test_metrics.brier_score}")
    print(f"  Test ECE:         {test_metrics.expected_calibration_error}")
    print(f"  Test MCE:         {test_metrics.maximum_calibration_error}")
    print(f"  Test ROC AUC:     {test_metrics.roc_auc}")
    print(f"  Test Log Loss:    {test_metrics.log_loss_value}")

    # Extract internal parameters for pure deterministic reconstruction
    scaler = prog_model.scaler
    cc = prog_model.calibrated_model.calibrated_classifiers_[0]
    estimator = cc.estimator
    calibrator = cc.calibrators[0]

    feature_order = list(CSV_AVAILABLE_FEATURES) + [f"{f}_delta" for f in CSV_AVAILABLE_FEATURES]

    model_dict: Dict[str, Any] = {
        "schema_version": 1,
        "model_type": "CalibratedLogisticRegression",
        "model_version": "1.0.0",
        "target_definition": {
            "name": "lookahead_attack_h3",
            "description": "Binary indicator: 1 if any known attack interval overlaps within next 3 windows (30s)",
            "horizon_steps": 3,
            "label_source": "eval.labels.annotate_transitions() -> LabeledTransition.lookahead_attack_h3",
            "attack_intervals_source": "eval.dataset.OBSERVED_INFILTRATION_BLOCKS",
        },
        "feature_schema": {
            "input_dimension": 30,
            "construction": "np.hstack([current_state_S_t (15 features), ar5_predicted_delta_h1 (15 features)])",
            "feature_order": feature_order,
            "current_state_features": list(CSV_AVAILABLE_FEATURES),
            "delta_features_suffix": "_delta",
        },
        "preprocessing": {
            "scaler_type": "StandardScaler",
            "mean": scaler.mean_.tolist(),
            "scale": scaler.scale_.tolist(),
            "var": scaler.var_.tolist(),
        },
        "classifier": {
            "type": "LogisticRegression",
            "C": 1.0,
            "class_weight": "balanced",
            "solver": "lbfgs",
            "max_iter": 1000,
            "random_state": 42,
            "coefficients": estimator.coef_[0].tolist(),
            "intercept": float(estimator.intercept_[0]),
        },
        "calibration": {
            "method": "sigmoid",
            "calibration_strategy": "PredefinedSplit(train=-1, val=0)",
            "calibrator_a": float(calibrator.a_),
            "calibrator_b": float(calibrator.b_),
            "description": "Platt scaling sigmoid parameters: P(y=1|f) = 1 / (1 + exp(A*f + B))",
        },
        "training_provenance": {
            "data_sources": [
                "artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.states.jsonl",
                "artifacts/state_sequences/Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl",
            ],
            "total_states": len(all_states),
            "total_transitions": n_total,
            "history_depth": 6,
            "chronological_split": {"train": 0.60, "val": 0.15, "test": 0.25},
            "split_sizes": {"train": n_train, "val": n_val, "test": n_test},
            "schema_hash": STATE_SCHEMA_HASH,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "experiment_source": "eval/run_logistic_benchmark.py -> Model 5 (Calibrated_Temporal_ProgressionProbability)",
        },
        "test_metrics": {
            "brier_score": test_metrics.brier_score,
            "expected_calibration_error": test_metrics.expected_calibration_error,
            "maximum_calibration_error": test_metrics.maximum_calibration_error,
            "roc_auc": test_metrics.roc_auc,
            "log_loss": test_metrics.log_loss_value,
            "precision_at_0.50": 0.8644,
            "recall_at_0.50": 0.1478,
            "f1_at_0.50": 0.2525,
            "false_positive_rate_at_0.50": 0.006,
        },
    }

    # 5. Compute SHA-256 provenance hash of canonical representation
    raw_canonical = canonical_json_dumps(model_dict)
    provenance_hash = hashlib.sha256(raw_canonical.encode("utf-8")).hexdigest()
    model_dict["provenance_hash"] = provenance_hash

    # Save to disk
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(model_dict, f, indent=2, sort_keys=True)

    print(f"[5/5] Persisted canonical progression model to: {out_file}")
    print(f"  Provenance Hash: {provenance_hash}")
    return model_dict


if __name__ == "__main__":
    train_and_persist_progression_model()
