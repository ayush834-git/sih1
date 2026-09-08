"""Calibrated Attack Progression Probability Model (SIH 26153).

Estimates calibrated empirical probability P(Attack progression within horizon h)
strictly separated from the heuristic Future Security Risk score.
Adheres strictly to the methodology guard: held-out test split is NEVER used for fitting
calibration parameters or model selection.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

import numpy as np
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, log_loss, roc_auc_score
from sklearn.model_selection import PredefinedSplit
from sklearn.preprocessing import StandardScaler


@dataclass(frozen=True)
class CalibrationMetrics:
    """Rigorous empirical calibration and discrimination metrics on held-out data."""
    brier_score: float              # Mean squared probability error (lower is better, [0, 1])
    expected_calibration_error: float # ECE across probability bins (lower is better, [0, 1])
    maximum_calibration_error: float  # MCE (maximum absolute calibration gap across bins)
    log_loss_value: float           # Cross-entropy loss
    roc_auc: float                  # Area under ROC curve
    bin_accuracies: List[float]     # Empirical positive frequency per bin
    bin_confidences: List[float]    # Mean predicted probability per bin
    bin_counts: List[int]           # Number of samples in each bin


def compute_ece(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    n_bins: int = 10,
) -> Tuple[float, float, List[float], List[float], List[int]]:
    """Compute Expected Calibration Error (ECE) and Maximum Calibration Error (MCE)."""
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    mce = 0.0
    bin_accs: List[float] = []
    bin_confs: List[float] = []
    bin_counts: List[int] = []

    total_samples = len(y_true)
    if total_samples == 0:
        return 0.0, 0.0, [], [], []

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        
        # Include upper boundary on the last bin
        if i == n_bins - 1:
            in_bin = (y_prob >= bin_lower) & (y_prob <= bin_upper)
        else:
            in_bin = (y_prob >= bin_lower) & (y_prob < bin_upper)

        n_in_bin = int(np.sum(in_bin))
        bin_counts.append(n_in_bin)

        if n_in_bin > 0:
            prop_true = float(np.mean(y_true[in_bin]))
            mean_conf = float(np.mean(y_prob[in_bin]))
            gap = abs(prop_true - mean_conf)
            ece += (n_in_bin / total_samples) * gap
            mce = max(mce, gap)
            bin_accs.append(prop_true)
            bin_confs.append(mean_conf)
        else:
            bin_accs.append(0.0)
            bin_confs.append(float((bin_lower + bin_upper) / 2.0))

    return ece, mce, bin_accs, bin_confs, bin_counts


class ProgressionProbabilityModel:
    """Supervised, calibrated model predicting attack progression probability over future horizons."""

    def __init__(
        self,
        feature_names: Sequence[str],
        horizon_steps: int = 3,
        calibration_method: str = "sigmoid",
    ) -> None:
        self.feature_names = list(feature_names)
        self.horizon_steps = horizon_steps
        self.calibration_method = calibration_method

        self.scaler = StandardScaler()
        self.base_classifier = LogisticRegression(
            C=1.0,
            class_weight="balanced",
            max_iter=1000,
            random_state=42,
            solver="lbfgs",
        )
        self.calibrated_model: CalibratedClassifierCV | None = None
        self.is_fitted: bool = False

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray | None = None,
        y_val: np.ndarray | None = None,
    ) -> ProgressionProbabilityModel:
        """Fit the model and calibrate strictly using training/validation data.
        
        Methodology Guard:
        - If X_val is provided, base model is fit on X_train, and calibration is fit on X_val (prefit).
        - If X_val is None, 5-fold cross-validation calibration is performed strictly within X_train.
        - The held-out test split is NEVER touched here.
        """
        if len(np.unique(y_train)) < 2:
            raise ValueError("Training set must contain both benign (0) and attack progression (1) samples")

        X_train_scaled = self.scaler.fit_transform(X_train)

        if X_val is not None and y_val is not None and len(np.unique(y_val)) >= 2:
            # Calibrate on validation split using PredefinedSplit (train=-1, val=0)
            X_val_scaled = self.scaler.transform(X_val)
            X_combined = np.vstack([X_train_scaled, X_val_scaled])
            y_combined = np.concatenate([y_train, y_val])
            test_fold = np.concatenate([
                -1 * np.ones(len(y_train), dtype=int),
                np.zeros(len(y_val), dtype=int),
            ])
            ps = PredefinedSplit(test_fold)
            self.calibrated_model = CalibratedClassifierCV(
                estimator=self.base_classifier,
                method=self.calibration_method,
                cv=ps,
            )
            self.calibrated_model.fit(X_combined, y_combined)
        else:
            # K-fold calibration strictly within training split
            self.calibrated_model = CalibratedClassifierCV(
                estimator=self.base_classifier,
                method=self.calibration_method,
                cv=5,
            )
            self.calibrated_model.fit(X_train_scaled, y_train)

        self.is_fitted = True
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict calibrated progression probability in [0, 1]."""
        if not self.is_fitted or self.calibrated_model is None:
            raise RuntimeError("Model must be fitted before predict_proba")
        X_scaled = self.scaler.transform(X)
        probs = self.calibrated_model.predict_proba(X_scaled)
        return probs[:, 1]

    def evaluate_on_test(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> CalibrationMetrics:
        """Evaluate calibration quality strictly on the held-out test split."""
        probs = self.predict_proba(X_test)
        
        brier = float(brier_score_loss(y_test, probs))
        ece, mce, bin_accs, bin_confs, bin_counts = compute_ece(y_test, probs, n_bins=10)
        
        try:
            logloss = float(log_loss(y_test, probs))
        except Exception:
            logloss = float("nan")

        try:
            auc = float(roc_auc_score(y_test, probs))
        except Exception:
            auc = float("nan")

        return CalibrationMetrics(
            brier_score=round(brier, 6),
            expected_calibration_error=round(ece, 6),
            maximum_calibration_error=round(mce, 6),
            log_loss_value=round(logloss, 6),
            roc_auc=round(auc, 6),
            bin_accuracies=[round(x, 4) for x in bin_accs],
            bin_confidences=[round(x, 4) for x in bin_confs],
            bin_counts=bin_counts,
        )
