"""Evaluation metrics, behavioural dimensions, and victory criterion logic."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import numpy as np


# Behavioural dimension feature mappings
BEHAVIOURAL_DIMENSIONS: dict[str, list[str]] = {
    "port_diversity": ["dst_port_diversity"],
    "syn_behaviour": ["syn_count", "syn_ratio"],
    "rst_behaviour": ["rst_count", "rst_ratio"],
    "rate_behaviour": ["packet_rate", "byte_rate"],
    "timing_iat_behaviour": ["iat_mean", "iat_std"],
    "destination_diversity": [],  # UNAVAILABLE in CSV source
}


@dataclass
class MetricReport:
    """Comprehensive metric report for a model evaluation on a dataset split."""
    model_name: str
    delta_mae: float
    delta_rmse: float
    directional_accuracy: float
    directional_accuracy_nonzero: float
    per_feature_mae: dict[str, float]
    interval_coverage_90: float | str
    behavioural_directional_accuracy: dict[str, float | str]
    n_samples: int
    n_features: int


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    feature_names: Sequence[str],
    lower_90: np.ndarray | None = None,
    upper_90: np.ndarray | None = None,
    model_name: str = "Model",
) -> MetricReport:
    """Compute primary, secondary, and behavioural metrics on held-out test data."""
    if y_true.shape != y_pred.shape:
        raise ValueError(f"Shape mismatch: y_true {y_true.shape} vs y_pred {y_pred.shape}")
        
    n_samples, n_features = y_true.shape
    
    # Delta-MAE (mean over all samples and features)
    delta_mae = float(np.mean(np.abs(y_true - y_pred)))
    
    # Delta-RMSE
    delta_rmse = float(np.sqrt(np.mean((y_true - y_pred) ** 2)))
    
    # Directional Accuracy
    # sign(x): -1 if x < 0, 0 if x == 0, 1 if x > 0
    sign_true = np.sign(y_true)
    sign_pred = np.sign(y_pred)
    matches = (sign_true == sign_pred)
    directional_acc = float(np.mean(matches))
    
    # Non-zero directional accuracy
    nonzero_mask = (sign_true != 0)
    if np.any(nonzero_mask):
        directional_acc_nonzero = float(np.mean(matches[nonzero_mask]))
    else:
        directional_acc_nonzero = 1.0
        
    # Per-feature MAE
    per_feat_mae: dict[str, float] = {}
    for j, f in enumerate(feature_names):
        per_feat_mae[f] = float(np.mean(np.abs(y_true[:, j] - y_pred[:, j])))
        
    # 90% Prediction Interval Coverage
    if lower_90 is not None and upper_90 is not None:
        in_interval = (y_true >= lower_90) & (y_true <= upper_90)
        coverage: float | str = float(np.mean(in_interval))
    else:
        coverage = "N/A"
        
    # Behavioural dimension directional accuracy
    behavioural_da: dict[str, float | str] = {}
    for dim_name, dim_features in BEHAVIOURAL_DIMENSIONS.items():
        if not dim_features:
            behavioural_da[dim_name] = "UNAVAILABLE"
            continue
        dim_indices = [feature_names.index(f) for f in dim_features if f in feature_names]
        if dim_indices:
            sub_true = sign_true[:, dim_indices]
            sub_pred = sign_pred[:, dim_indices]
            behavioural_da[dim_name] = float(np.mean(sub_true == sub_pred))
        else:
            behavioural_da[dim_name] = "UNAVAILABLE"
            
    return MetricReport(
        model_name=model_name,
        delta_mae=delta_mae,
        delta_rmse=delta_rmse,
        directional_accuracy=directional_acc,
        directional_accuracy_nonzero=directional_acc_nonzero,
        per_feature_mae=per_feat_mae,
        interval_coverage_90=coverage,
        behavioural_directional_accuracy=behavioural_da,
        n_samples=n_samples,
        n_features=n_features,
    )


@dataclass
class VictoryCriterionResult:
    """Result of victory criterion evaluation between a candidate model and baselines."""
    candidate_name: str
    baseline_name: str
    global_mae_improved: bool
    global_da_improved: bool
    block_fold_mae_improvements: list[bool]
    block_fold_da_improvements: list[bool]
    block_folds_passed: int
    total_valid_block_folds: int
    status: str  # "PASS", "MIXED", or "FAIL"
    explanation: str


def evaluate_victory_criterion(
    candidate_global: MetricReport,
    baseline_global: MetricReport,
    candidate_blocks: list[MetricReport],
    baseline_blocks: list[MetricReport],
) -> VictoryCriterionResult:
    """
    Frozen Victory Criterion:
    Model M beats baseline B only if BOTH:
    1. delta-MAE(M) < delta-MAE(B)
    2. directional_accuracy(M) > directional_accuracy(B)
    AND the improvement holds on at least 3 of 4 leave-one-observed-infiltration-block-out folds where valid.
    Otherwise report: MIXED or FAIL.
    """
    assert len(candidate_blocks) == len(baseline_blocks)
    
    global_mae_improved = candidate_global.delta_mae < baseline_global.delta_mae
    global_da_improved = candidate_global.directional_accuracy > baseline_global.directional_accuracy
    
    block_mae_impr: list[bool] = []
    block_da_impr: list[bool] = []
    
    for c_blk, b_blk in zip(candidate_blocks, baseline_blocks):
        mae_win = c_blk.delta_mae < b_blk.delta_mae
        da_win = c_blk.directional_accuracy > b_blk.directional_accuracy
        block_mae_impr.append(mae_win)
        block_da_impr.append(da_win)
        
    # A block fold passes if both MAE and DA improved on that fold
    block_wins = [m and d for m, d in zip(block_mae_impr, block_da_impr)]
    n_passed = sum(block_wins)
    total_valid = len(candidate_blocks)
    
    if global_mae_improved and global_da_improved and n_passed >= 3:
        status = "PASS"
        explanation = f"{candidate_global.model_name} beat {baseline_global.model_name} on global MAE ({candidate_global.delta_mae:.4f} vs {baseline_global.delta_mae:.4f}), global DA ({candidate_global.directional_accuracy:.4f} vs {baseline_global.directional_accuracy:.4f}), and passed {n_passed}/{total_valid} block folds."
    elif (global_mae_improved or global_da_improved) or n_passed > 0:
        status = "MIXED"
        explanation = f"{candidate_global.model_name} vs {baseline_global.model_name} achieved mixed results (Global MAE win: {global_mae_improved}, Global DA win: {global_da_improved}, Block fold wins: {n_passed}/{total_valid})."
    else:
        status = "FAIL"
        explanation = f"{candidate_global.model_name} failed to beat {baseline_global.model_name} (Global MAE win: {global_mae_improved}, Global DA win: {global_da_improved}, Block fold wins: {n_passed}/{total_valid})."
        
    return VictoryCriterionResult(
        candidate_name=candidate_global.model_name,
        baseline_name=baseline_global.model_name,
        global_mae_improved=global_mae_improved,
        global_da_improved=global_da_improved,
        block_fold_mae_improvements=block_mae_impr,
        block_fold_da_improvements=block_da_impr,
        block_folds_passed=n_passed,
        total_valid_block_folds=total_valid,
        status=status,
        explanation=explanation,
    )
