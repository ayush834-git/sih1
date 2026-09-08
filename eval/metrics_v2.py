"""Metrics, normalization, and victory criterion logic for Delta-State Baseline V2."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import numpy as np


@dataclass
class RobustScaleStatistics:
    """Per-feature scale statistics computed strictly on training target data."""
    feature_names: list[str]
    medians: np.ndarray      # Shape: (D,)
    iqrs: np.ndarray         # Shape: (D,)
    mads: np.ndarray         # Shape: (D,)
    stds: np.ndarray         # Shape: (D,)
    effective_scales: np.ndarray  # Shape: (D,)


def compute_training_scales(y_train: np.ndarray, feature_names: Sequence[str]) -> RobustScaleStatistics:
    """
    Compute robust scale per target feature strictly on training targets.
    Scale definition:
    1. IQR = Q75 - Q25
    2. Fallback to MAD * 1.4826 if IQR == 0
    3. Fallback to std if MAD == 0
    4. Fallback to 1.0 if std == 0
    """
    n_samples, n_features = y_train.shape
    medians = np.median(y_train, axis=0)
    q25 = np.percentile(y_train, 25.0, axis=0)
    q75 = np.percentile(y_train, 75.0, axis=0)
    iqrs = q75 - q25
    
    # MAD: Median Absolute Deviation from median
    abs_dev = np.abs(y_train - medians)
    mads = np.median(abs_dev, axis=0) * 1.4826
    stds = np.std(y_train, axis=0)
    
    effective_scales = np.zeros(n_features, dtype=np.float64)
    for j in range(n_features):
        if iqrs[j] > 1e-9:
            effective_scales[j] = iqrs[j]
        elif mads[j] > 1e-9:
            effective_scales[j] = mads[j]
        elif stds[j] > 1e-9:
            effective_scales[j] = stds[j]
        else:
            effective_scales[j] = 1.0
            
    return RobustScaleStatistics(
        feature_names=list(feature_names),
        medians=medians,
        iqrs=iqrs,
        mads=mads,
        stds=stds,
        effective_scales=effective_scales,
    )


@dataclass
class MetricReportV2:
    """Comprehensive Metric Report V2 with both raw and scale-normalized evaluations."""
    model_name: str
    delta_mae_raw: float
    delta_rmse_raw: float
    delta_mae_normalized: float
    delta_rmse_normalized: float
    median_mae_normalized: float
    directional_accuracy: float
    directional_accuracy_nonzero: float
    per_feature_raw_mae: dict[str, float]
    per_feature_normalized_mae: dict[str, float]
    per_feature_directional_accuracy: dict[str, float]
    per_feature_directional_accuracy_nonzero: dict[str, float]
    interval_coverage_90: float | str
    behavioural_directional_accuracy: dict[str, float | str]
    n_samples: int
    n_features: int


def compute_metrics_v2(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    feature_names: Sequence[str],
    scales: RobustScaleStatistics,
    lower_90: np.ndarray | None = None,
    upper_90: np.ndarray | None = None,
    model_name: str = "Model",
) -> MetricReportV2:
    """Compute raw and scale-normalized metrics on held-out data using fixed training scales."""
    if y_true.shape != y_pred.shape:
        raise ValueError(f"Shape mismatch: y_true {y_true.shape} vs y_pred {y_pred.shape}")
        
    n_samples, n_features = y_true.shape
    raw_abs_err = np.abs(y_true - y_pred)
    raw_sq_err = (y_true - y_pred) ** 2
    
    # Raw global metrics
    raw_mae = float(np.mean(raw_abs_err))
    raw_rmse = float(np.sqrt(np.mean(raw_sq_err)))
    
    # Scale-normalized errors
    scale_matrix = np.tile(scales.effective_scales, (n_samples, 1))
    norm_abs_err = raw_abs_err / scale_matrix
    norm_sq_err = ( (y_true - y_pred) / scale_matrix ) ** 2
    
    norm_mae = float(np.mean(norm_abs_err))
    norm_rmse = float(np.sqrt(np.mean(norm_sq_err)))
    median_norm_mae = float(np.median(norm_abs_err))
    
    # Directional accuracy
    sign_true = np.sign(y_true)
    sign_pred = np.sign(y_pred)
    matches = (sign_true == sign_pred)
    da_overall = float(np.mean(matches))
    
    nonzero_mask = (sign_true != 0)
    da_nonzero = float(np.mean(matches[nonzero_mask])) if np.any(nonzero_mask) else 1.0
    
    # Per-feature breakdowns
    per_feat_raw_mae: dict[str, float] = {}
    per_feat_norm_mae: dict[str, float] = {}
    per_feat_da: dict[str, float] = {}
    per_feat_da_nz: dict[str, float] = {}
    
    for j, f in enumerate(feature_names):
        per_feat_raw_mae[f] = float(np.mean(raw_abs_err[:, j]))
        per_feat_norm_mae[f] = float(np.mean(norm_abs_err[:, j]))
        per_feat_da[f] = float(np.mean(matches[:, j]))
        nz_j = (sign_true[:, j] != 0)
        if np.any(nz_j):
            per_feat_da_nz[f] = float(np.mean(matches[nz_j, j]))
        else:
            per_feat_da_nz[f] = 1.0
            
    # Interval coverage
    if lower_90 is not None and upper_90 is not None:
        in_interval = (y_true >= lower_90) & (y_true <= upper_90)
        coverage: float | str = float(np.mean(in_interval))
    else:
        coverage = "N/A"
        
    # Behavioural dimensions
    from eval.metrics import BEHAVIOURAL_DIMENSIONS
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
            
    return MetricReportV2(
        model_name=model_name,
        delta_mae_raw=raw_mae,
        delta_rmse_raw=raw_rmse,
        delta_mae_normalized=norm_mae,
        delta_rmse_normalized=norm_rmse,
        median_mae_normalized=median_norm_mae,
        directional_accuracy=da_overall,
        directional_accuracy_nonzero=da_nonzero,
        per_feature_raw_mae=per_feat_raw_mae,
        per_feature_normalized_mae=per_feat_norm_mae,
        per_feature_directional_accuracy=per_feat_da,
        per_feature_directional_accuracy_nonzero=per_feat_da_nz,
        interval_coverage_90=coverage,
        behavioural_directional_accuracy=behavioural_da,
        n_samples=n_samples,
        n_features=n_features,
    )


@dataclass
class VictoryCriterionV2Result:
    """Evaluation result for V2 Primary (Normalized) and Secondary (Raw) criteria."""
    candidate_name: str
    baseline_name: str
    # Primary (Normalized MAE + DA)
    norm_mae_improved: bool
    norm_da_improved: bool
    block_norm_mae_improvements: list[bool]
    block_norm_da_improvements: list[bool]
    block_folds_passed_norm: int
    v2_primary_status: str  # "IMPROVED", "MIXED", "NO IMPROVEMENT"
    # Secondary (Raw MAE + DA)
    raw_mae_improved: bool
    raw_da_improved: bool
    block_raw_mae_improvements: list[bool]
    block_raw_da_improvements: list[bool]
    block_folds_passed_raw: int
    v1_raw_status: str      # "PASS", "MIXED", "FAIL"
    explanation: str


def evaluate_victory_criterion_v2(
    cand_global: MetricReportV2,
    base_global: MetricReportV2,
    cand_blocks: list[MetricReportV2],
    base_blocks: list[MetricReportV2],
) -> VictoryCriterionV2Result:
    """Evaluate both V2 Normalized criterion and original V1 Raw criterion."""
    assert len(cand_blocks) == len(base_blocks)
    total_valid = len(cand_blocks)
    
    # Primary: Normalized MAE & DA
    norm_mae_impr = cand_global.delta_mae_normalized < base_global.delta_mae_normalized
    norm_da_impr = cand_global.directional_accuracy > base_global.directional_accuracy
    
    block_norm_mae_impr = [c.delta_mae_normalized < b.delta_mae_normalized for c, b in zip(cand_blocks, base_blocks)]
    block_norm_da_impr = [c.directional_accuracy > b.directional_accuracy for c, b in zip(cand_blocks, base_blocks)]
    block_norm_wins = [m and d for m, d in zip(block_norm_mae_impr, block_norm_da_impr)]
    n_passed_norm = sum(block_norm_wins)
    
    if norm_mae_impr and norm_da_impr and n_passed_norm >= 3:
        v2_status = "IMPROVED"
    elif (norm_mae_impr or norm_da_impr) or n_passed_norm > 0:
        v2_status = "MIXED"
    else:
        v2_status = "NO IMPROVEMENT"
        
    # Secondary: Raw MAE & DA (Original V1 criterion)
    raw_mae_impr = cand_global.delta_mae_raw < base_global.delta_mae_raw
    raw_da_impr = cand_global.directional_accuracy > base_global.directional_accuracy
    
    block_raw_mae_impr = [c.delta_mae_raw < b.delta_mae_raw for c, b in zip(cand_blocks, base_blocks)]
    block_raw_da_impr = [c.directional_accuracy > b.directional_accuracy for c, b in zip(cand_blocks, base_blocks)]
    block_raw_wins = [m and d for m, d in zip(block_raw_mae_impr, block_raw_da_impr)]
    n_passed_raw = sum(block_raw_wins)
    
    if raw_mae_impr and raw_da_impr and n_passed_raw >= 3:
        v1_status = "PASS"
    elif (raw_mae_impr or raw_da_impr) or n_passed_raw > 0:
        v1_status = "MIXED"
    else:
        v1_status = "FAIL"
        
    explanation = (
        f"V2 Normalized: [{v2_status}] (Norm MAE win: {norm_mae_impr} [{cand_global.delta_mae_normalized:.4f} vs {base_global.delta_mae_normalized:.4f}], "
        f"DA win: {norm_da_impr} [{cand_global.directional_accuracy:.4f} vs {base_global.directional_accuracy:.4f}], Block wins: {n_passed_norm}/{total_valid}). | "
        f"V1 Raw: [{v1_status}] (Raw MAE win: {raw_mae_impr}, DA win: {raw_da_impr}, Block wins: {n_passed_raw}/{total_valid})."
    )
    
    return VictoryCriterionV2Result(
        candidate_name=cand_global.model_name,
        baseline_name=base_global.model_name,
        norm_mae_improved=norm_mae_impr,
        norm_da_improved=norm_da_impr,
        block_norm_mae_improvements=block_norm_mae_impr,
        block_norm_da_improvements=block_norm_da_impr,
        block_folds_passed_norm=n_passed_norm,
        v2_primary_status=v2_status,
        raw_mae_improved=raw_mae_impr,
        raw_da_improved=raw_da_impr,
        block_raw_mae_improvements=block_raw_mae_impr,
        block_raw_da_improvements=block_raw_da_impr,
        block_folds_passed_raw=n_passed_raw,
        v1_raw_status=v1_status,
        explanation=explanation,
    )
