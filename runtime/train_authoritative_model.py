"""Train, validate, persist and verify the authoritative AR(5) model for runtime use (SIH 26153).

This script:
1. Loads CIC-IDS2018 state sequences (Wednesday + Thursday)
2. Extracts transitions with history_depth=6 for AR(p=1..5)
3. Splits chronologically 60/15/25
4. Computes training-only robust scales
5. Trains ARStyleBaselineV2 with auto-tuned p
6. Persists: model coefficients, scales, metadata → artifacts/models/ar5_authoritative/
7. Verifies non-zero forecast on demo_recon_15s scenario
8. Loads the persisted model and verifies round-trip equivalence
"""
from __future__ import annotations

import json
import hashlib
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

from eval.dataset import (
    CSV_AVAILABLE_FEATURES,
    chronological_split,
    extract_transitions,
    load_states_from_jsonl,
    samples_to_arrays,
)
from eval.metrics_v2 import (
    RobustScaleStatistics,
    compute_metrics_v2,
    compute_training_scales,
)
from eval.models_v2 import ARStyleBaselineV2
from scenarios.demo.scenarios import get_demo_scenario_states
from scenarios.demo.engine import LiveDemoEngine


# ────────────────────────────────────────────────────────────
# Persistence helpers
# ────────────────────────────────────────────────────────────

def persist_ar_model(
    model: ARStyleBaselineV2,
    scales: RobustScaleStatistics,
    output_dir: Path,
    metadata: dict[str, Any],
) -> Path:
    """Persist AR model coefficients, scales, and metadata to disk."""
    output_dir.mkdir(parents=True, exist_ok=True)
    n_features = len(model.models)

    # 1. Model coefficients: one file per feature
    coeffs_dir = output_dir / "coefficients"
    coeffs_dir.mkdir(exist_ok=True)
    for j, reg in enumerate(model.models):
        feat_name = CSV_AVAILABLE_FEATURES[j]
        np.savez_compressed(
            coeffs_dir / f"{feat_name}.npz",
            coef=reg.coef_,
            intercept=np.array([reg.intercept_]),
        )

    # 2. Scales
    np.savez_compressed(
        output_dir / "scales.npz",
        feature_names=np.array(scales.feature_names),
        medians=scales.medians,
        iqrs=scales.iqrs,
        mads=scales.mads,
        stds=scales.stds,
        effective_scales=scales.effective_scales,
    )

    # 3. Metadata
    meta = {
        "model_name": model.model_name,
        "model_family": model.model_family,
        "selected_p": model.selected_p,
        "n_features": n_features,
        "feature_names": list(CSV_AVAILABLE_FEATURES),
        "selected_hyperparameters": model.selected_hyperparameters,
        "created_at": datetime.now().isoformat(),
        **metadata,
    }
    with open(output_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return output_dir


def load_ar_model(model_dir: Path) -> tuple[ARStyleBaselineV2, RobustScaleStatistics]:
    """Load a persisted AR model and scales from disk."""
    from sklearn.linear_model import LinearRegression

    # 1. Metadata
    with open(model_dir / "metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    selected_p = meta["selected_p"]
    feature_names = meta["feature_names"]
    n_features = len(feature_names)

    # 2. Model coefficients
    coeffs_dir = model_dir / "coefficients"
    models = []
    for feat_name in feature_names:
        data = np.load(coeffs_dir / f"{feat_name}.npz")
        reg = LinearRegression()
        reg.coef_ = data["coef"]
        reg.intercept_ = float(data["intercept"][0])
        models.append(reg)

    ar_model = ARStyleBaselineV2(fixed_p=selected_p)
    ar_model.selected_p = selected_p
    ar_model.models = models
    ar_model.model_name = meta["model_name"]
    ar_model.selected_hyperparameters = meta.get("selected_hyperparameters", {})

    # 3. Scales
    scales_data = np.load(model_dir / "scales.npz", allow_pickle=True)
    scales = RobustScaleStatistics(
        feature_names=list(scales_data["feature_names"]),
        medians=scales_data["medians"],
        iqrs=scales_data["iqrs"],
        mads=scales_data["mads"],
        stds=scales_data["stds"],
        effective_scales=scales_data["effective_scales"],
    )

    return ar_model, scales


# ────────────────────────────────────────────────────────────
# Main training pipeline
# ────────────────────────────────────────────────────────────

def train_and_persist(
    wed_path: str | Path = "artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.states.jsonl",
    thu_path: str | Path = "artifacts/state_sequences/Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl",
    output_dir: str | Path = "artifacts/models/ar5_authoritative",
    history_depth: int = 6,
) -> dict[str, Any]:
    """Train the authoritative AR(5) model and persist it for runtime use."""
    t0 = time.time()
    out_dir = Path(output_dir)

    print("=" * 75)
    print("SIH 26153 — AUTHORITATIVE AR(5) TRAINING & PERSISTENCE")
    print("=" * 75)

    # ── 1. Load state sequences ───────────────────────────
    print("\n[1/8] Loading state sequences...")
    wed_states = load_states_from_jsonl(wed_path)
    thu_states = load_states_from_jsonl(thu_path)
    all_states = wed_states + thu_states
    print(f"  Wednesday: {len(wed_states)} states")
    print(f"  Thursday:  {len(thu_states)} states")
    print(f"  Combined:  {len(all_states)} states")

    # ── 2. Extract transitions ────────────────────────────
    print(f"\n[2/8] Extracting transitions (history_depth={history_depth})...")
    all_transitions, dropped = extract_transitions(all_states, history_depth=history_depth)
    print(f"  Valid transitions: {len(all_transitions)}")
    for reason, count in dropped.items():
        if count > 0:
            print(f"  Dropped ({reason}): {count}")

    # ── 3. Chronological split ────────────────────────────
    print("\n[3/8] Chronological split 60/15/25...")
    tr_s, val_s, te_s = chronological_split(all_transitions, 0.60, 0.15, 0.25)
    tr = samples_to_arrays(tr_s)
    va = samples_to_arrays(val_s)
    te = samples_to_arrays(te_s)
    print(f"  Train: {tr.X.shape[0]} | Val: {va.X.shape[0]} | Test: {te.X.shape[0]}")

    # ── 4. Compute training-only robust scales ────────────
    print("\n[4/8] Computing training-only robust scales...")
    train_scales = compute_training_scales(tr.y, CSV_AVAILABLE_FEATURES)
    print("  Feature scales (IQR / Effective):")
    for fn, sv in zip(train_scales.feature_names, train_scales.effective_scales):
        print(f"    {fn:22s}: {sv:14.4f}")

    # ── 5. Train AR(best p) with validation tuning ────────
    print("\n[5/8] Training AR(best p) model with p in {1,2,3,4,5}...")
    ar_model = ARStyleBaselineV2()  # candidate_p defaults to (1,2,3,4,5)
    ar_model.fit(tr.X, tr.y, tr.X_deltas, va.X, va.y, va.X_deltas, scales=train_scales)
    print(f"  Selected p: {ar_model.selected_p}")
    print(f"  Model name: {ar_model.model_name}")
    print(f"  Val normalized MAE: {ar_model.selected_hyperparameters.get('val_norm_mae', 'N/A')}")

    # ── 6. Evaluate on test set ───────────────────────────
    print("\n[6/8] Evaluating on held-out test set...")
    preds_te = ar_model.predict(te.X, te.X_deltas, n_features=len(CSV_AVAILABLE_FEATURES))
    metrics = compute_metrics_v2(te.y, preds_te, CSV_AVAILABLE_FEATURES, train_scales, model_name=ar_model.model_name)

    print(f"  Test Normalized MAE: {metrics.delta_mae_normalized:.6f}")
    print(f"  Test Normalized RMSE: {metrics.delta_rmse_normalized:.6f}")
    print(f"  Test Directional Accuracy: {metrics.directional_accuracy:.4f}")
    print(f"  Test DA (non-zero only): {metrics.directional_accuracy_nonzero:.4f}")
    print(f"  Test Raw MAE: {metrics.delta_mae_raw:.4e}")
    print("  Per-feature Normalized MAE:")
    for fn in CSV_AVAILABLE_FEATURES:
        nmae = metrics.per_feature_normalized_mae.get(fn, 0.0)
        da = metrics.per_feature_directional_accuracy.get(fn, 0.0)
        print(f"    {fn:22s}: NMAE={nmae:.4f}  DA={da:.4f}")

    # ── 7. Persist model ──────────────────────────────────
    print(f"\n[7/8] Persisting model to {out_dir}...")
    persist_metadata = {
        "training_states_count": len(all_states),
        "training_transitions_count": len(all_transitions),
        "train_samples": tr.X.shape[0],
        "val_samples": va.X.shape[0],
        "test_samples": te.X.shape[0],
        "test_normalized_mae": float(metrics.delta_mae_normalized),
        "test_directional_accuracy": float(metrics.directional_accuracy),
        "test_raw_mae": float(metrics.delta_mae_raw),
        "history_depth": history_depth,
        "wed_source": str(wed_path),
        "thu_source": str(thu_path),
    }
    persist_ar_model(ar_model, train_scales, out_dir, persist_metadata)
    print("  [OK] Model coefficients saved")
    print("  [OK] Scales saved")
    print("  [OK] Metadata saved")

    # ── 8. Verification ───────────────────────────────────
    print("\n[8/8] Verification...")

    # 8a. Round-trip: load and verify predictions match
    print("  [8a] Round-trip coefficient verification...")
    loaded_model, loaded_scales = load_ar_model(out_dir)
    preds_roundtrip = loaded_model.predict(te.X, te.X_deltas, n_features=len(CSV_AVAILABLE_FEATURES))
    max_diff = float(np.max(np.abs(preds_te - preds_roundtrip)))
    print(f"    Max prediction difference after round-trip: {max_diff:.2e}")
    assert max_diff < 1e-10, f"Round-trip verification failed: max_diff={max_diff}"
    print("    [OK] Round-trip verification PASSED")

    # 8b. Non-zero forecast on demo scenario
    print("  [8b] Non-zero forecast verification on demo_recon_15s...")
    demo_engine = LiveDemoEngine(ar_model=loaded_model, scales=loaded_scales)
    demo_states = get_demo_scenario_states("demo_recon_15s")
    events = list(demo_engine.stream_scenario(demo_states))

    any_nonzero_forecast = False
    for evt in events:
        deltas = evt.predicted_deltas_h1
        if any(abs(v) > 1e-8 for v in deltas.values()):
            any_nonzero_forecast = True
            break

    if any_nonzero_forecast:
        print("    [OK] Non-zero forecast deltas confirmed")
    else:
        print("    [WARN] WARNING: All forecast deltas are still zero. AR model may need more history warming.")

    # Print sample forecasts for inspection
    print("\n  Sample forecast deltas from demo_recon_15s:")
    for evt in events:
        step = evt.step_index
        pd_delta = evt.predicted_deltas_h1.get("dst_port_diversity_delta", 0.0)
        fc_delta = evt.predicted_deltas_h1.get("flow_count_delta", 0.0)
        br_delta = evt.predicted_deltas_h1.get("byte_rate_delta", 0.0)
        risk = evt.current_risk_score
        stage = evt.primary_stage
        prio = evt.priority_level
        print(f"    T{step:02d}: dPort={pd_delta:+8.2f} dFlow={fc_delta:+8.2f} dByte={br_delta:+10.2f} | Risk={risk:.3f} Stage={stage:30s} Prio={prio}")

    elapsed = time.time() - t0
    print(f"\n{'=' * 75}")
    print(f"TRAINING COMPLETE in {elapsed:.1f}s")
    print(f"Model: {ar_model.model_name} (p={ar_model.selected_p})")
    print(f"Artifact: {out_dir}")
    print(f"{'=' * 75}")

    return {
        "model_name": ar_model.model_name,
        "selected_p": ar_model.selected_p,
        "output_dir": str(out_dir),
        "test_normalized_mae": float(metrics.delta_mae_normalized),
        "test_directional_accuracy": float(metrics.directional_accuracy),
        "non_zero_forecast_verified": any_nonzero_forecast,
        "elapsed_seconds": elapsed,
    }


if __name__ == "__main__":
    result = train_and_persist()
    print(f"\nResult: {json.dumps(result, indent=2)}")
