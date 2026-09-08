"""Baseline ladder models V2 supporting arbitrary AR lag orders and normalized validation tuning."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import numpy as np
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.linear_model import LinearRegression, Ridge
from sklearn.preprocessing import RobustScaler

from eval.metrics_v2 import RobustScaleStatistics


class ZeroChangeBaselineV2:
    """B1. Zero-Change: Predicts ΔS_hat = 0."""
    def __init__(self) -> None:
        self.model_name = "B1_ZeroChange"
        self.model_family = "ZeroChange"
        self.selected_hyperparameters: dict[str, Any] = {}
        
    def fit(self, *args: Any, **kwargs: Any) -> ZeroChangeBaselineV2:
        return self
        
    def predict(self, X: np.ndarray, X_deltas: np.ndarray | None = None, n_features: int = 15) -> np.ndarray:
        return np.zeros((X.shape[0], n_features), dtype=np.float64)


class PersistenceBaselineV2:
    """B2. Persistence in Delta space: Predicts ΔS_hat_t = ΔS_{t-1}."""
    def __init__(self) -> None:
        self.model_name = "B2_Persistence"
        self.model_family = "Persistence"
        self.selected_hyperparameters: dict[str, Any] = {}
        
    def fit(self, *args: Any, **kwargs: Any) -> PersistenceBaselineV2:
        return self
        
    def predict(self, X: np.ndarray, X_deltas: np.ndarray, n_features: int = 15) -> np.ndarray:
        if X_deltas.shape[1] < n_features:
            return np.zeros((X.shape[0], n_features), dtype=np.float64)
        return X_deltas[:, -n_features:].copy()


class EWMABaselineV2:
    """B3. EWMA Baseline: Exponentially weighted moving average of past deltas."""
    def __init__(self, candidate_alphas: Sequence[float] = (0.1, 0.3, 0.5)) -> None:
        self.model_name = "B3_EWMA"
        self.model_family = "EWMA"
        self.candidate_alphas = tuple(candidate_alphas)
        self.selected_alpha: float = 0.3
        self.selected_hyperparameters: dict[str, Any] = {}
        
    def _compute_ewma(self, X_deltas: np.ndarray, alpha: float, n_features: int) -> np.ndarray:
        n_samples = X_deltas.shape[0]
        n_lags = X_deltas.shape[1] // n_features
        if n_lags <= 0:
            return np.zeros((n_samples, n_features), dtype=np.float64)
        if n_lags == 1:
            return X_deltas[:, :n_features].copy()
            
        preds = np.zeros((n_samples, n_features), dtype=np.float64)
        weights = []
        for lag_idx in range(n_lags):
            k = (n_lags - 1) - lag_idx  # 0 for newest
            w = alpha * ((1.0 - alpha) ** k)
            weights.append(w)
            lag_slice = X_deltas[:, lag_idx * n_features : (lag_idx + 1) * n_features]
            preds += w * lag_slice
        sum_w = sum(weights)
        if sum_w > 0:
            preds /= sum_w
        return preds
        
    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_deltas_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        X_deltas_val: np.ndarray,
        scales: RobustScaleStatistics | None = None,
    ) -> EWMABaselineV2:
        n_features = y_train.shape[1]
        best_alpha = self.candidate_alphas[0]
        best_nmae = float("inf")
        scale_vec = scales.effective_scales if scales is not None else np.ones(n_features)
        
        for alpha in self.candidate_alphas:
            preds_val = self._compute_ewma(X_deltas_val, alpha, n_features)
            norm_err = np.abs(preds_val - y_val) / scale_vec
            nmae = float(np.mean(norm_err))
            if nmae < best_nmae:
                best_nmae = nmae
                best_alpha = alpha
                
        self.selected_alpha = best_alpha
        self.selected_hyperparameters = {"alpha": self.selected_alpha, "val_norm_mae": best_nmae}
        return self
        
    def predict(self, X: np.ndarray, X_deltas: np.ndarray, n_features: int = 15) -> np.ndarray:
        return self._compute_ewma(X_deltas, self.selected_alpha, n_features)


class ARStyleBaselineV2:
    """
    B4. AR-style Baseline supporting arbitrary lag order p in {1, 2, 3, 4, 5}.
    Tuned on validation normalized MAE.
    """
    def __init__(self, fixed_p: int | None = None, candidate_p: Sequence[int] = (1, 2, 3, 4, 5)) -> None:
        self.fixed_p = fixed_p
        self.candidate_p = tuple(candidate_p)
        self.selected_p: int = fixed_p if fixed_p is not None else 2
        self.model_name = f"B4_AR_p{self.selected_p}" if fixed_p is not None else "B4_AR_best"
        self.model_family = "AR-style"
        self.models: list[LinearRegression] = []
        self.selected_hyperparameters: dict[str, Any] = {}
        
    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_deltas_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        X_deltas_val: np.ndarray,
        scales: RobustScaleStatistics | None = None,
    ) -> ARStyleBaselineV2:
        n_features = y_train.shape[1]
        max_available_p = X_deltas_train.shape[1] // n_features
        scale_vec = scales.effective_scales if scales is not None else np.ones(n_features)
        
        if self.fixed_p is not None:
            if self.fixed_p > max_available_p:
                raise ValueError(
                    f"AR({self.fixed_p}) requires at least {self.fixed_p + 1} consecutive states "
                    f"(history_depth >= {self.fixed_p + 1}), but only {max_available_p + 1} states "
                    f"({max_available_p} historical deltas) were provided."
                )
            valid_candidates = [self.fixed_p]
        else:
            valid_candidates = [p for p in self.candidate_p if 1 <= p <= max_available_p]
            if not valid_candidates:
                raise ValueError(
                    f"AR candidates {self.candidate_p} require at least 2 consecutive states, "
                    f"but only {max_available_p + 1} states were provided."
                )
                
        best_p = valid_candidates[0]
        best_nmae = float("inf")
        best_models: list[LinearRegression] = []
        
        for p in valid_candidates:
            p_train = X_deltas_train[:, -p * n_features :]
            p_val = X_deltas_val[:, -p * n_features :]
            
            models = []
            val_preds = np.zeros_like(y_val)
            for j in range(n_features):
                lag_indices = [k * n_features + j for k in range(p)]
                feat_X_train = p_train[:, lag_indices]
                feat_X_val = p_val[:, lag_indices]
                
                reg = LinearRegression()
                reg.fit(feat_X_train, y_train[:, j])
                models.append(reg)
                val_preds[:, j] = reg.predict(feat_X_val)
                
            norm_err = np.abs(val_preds - y_val) / scale_vec
            nmae = float(np.mean(norm_err))
            if nmae < best_nmae:
                best_nmae = nmae
                best_p = p
                best_models = models
                
        self.selected_p = best_p
        self.models = best_models
        if self.fixed_p is None:
            self.model_name = f"B4_AR_best(p={self.selected_p})"
        self.selected_hyperparameters = {"p": self.selected_p, "val_norm_mae": best_nmae}
        return self
        
    def predict(self, X: np.ndarray, X_deltas: np.ndarray, n_features: int = 15) -> np.ndarray:
        n_samples = X.shape[0]
        preds = np.zeros((n_samples, n_features), dtype=np.float64)
        p = self.selected_p
        p_deltas = X_deltas[:, -p * n_features :]
        
        for j in range(n_features):
            lag_indices = [k * n_features + j for k in range(p)]
            feat_X = p_deltas[:, lag_indices]
            preds[:, j] = self.models[j].predict(feat_X)
            
        return preds


class RidgeLearnedModelV2:
    """
    B5. Ridge Regression V2:
    Fits per-feature Ridge regression mapping scaled history to ΔS_j,
    tuning alpha on validation normalized MAE.
    """
    def __init__(self, candidate_alphas: Sequence[float] = (0.01, 0.1, 1.0, 10.0, 100.0, 1000.0)) -> None:
        self.model_name = "B5_Ridge"
        self.model_family = "Ridge"
        self.candidate_alphas = tuple(candidate_alphas)
        self.scaler: RobustScaler = RobustScaler()
        self.models: list[Ridge] = []
        self.residual_lower_90: np.ndarray | None = None
        self.residual_upper_90: np.ndarray | None = None
        self.selected_hyperparameters: dict[str, Any] = {}
        
    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        scales: RobustScaleStatistics | None = None,
    ) -> RidgeLearnedModelV2:
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        n_features = y_train.shape[1]
        scale_vec = scales.effective_scales if scales is not None else np.ones(n_features)
        
        # Fit per-feature Ridge to prevent high-scale features from overwhelming low-scale features
        best_alphas = []
        best_models = []
        val_preds = np.zeros_like(y_val)
        
        for j in range(n_features):
            feat_best_alpha = self.candidate_alphas[0]
            feat_best_mae = float("inf")
            feat_best_model = None
            
            for alpha in self.candidate_alphas:
                reg = Ridge(alpha=alpha, random_state=42)
                reg.fit(X_train_scaled, y_train[:, j])
                p_val = reg.predict(X_val_scaled)
                mae = float(np.mean(np.abs(p_val - y_val[:, j])))
                if mae < feat_best_mae:
                    feat_best_mae = mae
                    feat_best_alpha = alpha
                    feat_best_model = reg
                    
            best_alphas.append(feat_best_alpha)
            best_models.append(feat_best_model)
            val_preds[:, j] = feat_best_model.predict(X_val_scaled)
            
        self.models = best_models
        
        # Compute training residuals for 90% empirical intervals
        train_preds = np.zeros_like(y_train)
        for j in range(n_features):
            train_preds[:, j] = self.models[j].predict(X_train_scaled)
        train_residuals = y_train - train_preds
        self.residual_lower_90 = np.percentile(train_residuals, 5.0, axis=0)
        self.residual_upper_90 = np.percentile(train_residuals, 95.0, axis=0)
        
        norm_err = np.abs(val_preds - y_val) / scale_vec
        self.selected_hyperparameters = {
            "per_feature_alphas": {scales.feature_names[j]: best_alphas[j] for j in range(n_features)} if scales else best_alphas,
            "val_norm_mae": float(np.mean(norm_err)),
        }
        return self
        
    def predict(self, X: np.ndarray, X_deltas: np.ndarray | None = None, n_features: int = 15) -> np.ndarray:
        X_scaled = self.scaler.transform(X)
        preds = np.zeros((X.shape[0], n_features), dtype=np.float64)
        for j in range(n_features):
            preds[:, j] = self.models[j].predict(X_scaled)
        return preds
        
    def predict_with_interval(self, X: np.ndarray, n_features: int = 15) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        preds = self.predict(X, n_features=n_features)
        lower = preds + self.residual_lower_90
        upper = preds + self.residual_upper_90
        return preds, lower, upper


class GBDTLearnedModelV2:
    """
    B6. GBDT V2:
    HistGradientBoostingRegressor per feature, tuned on validation normalized MAE.
    """
    def __init__(self, candidate_params: Sequence[dict[str, Any]] | None = None) -> None:
        self.model_name = "B6_GBDT"
        self.model_family = "GBDT"
        if candidate_params is None:
            self.candidate_params = (
                {"max_iter": 50, "learning_rate": 0.05, "max_depth": 4, "min_samples_leaf": 20},
                {"max_iter": 100, "learning_rate": 0.1, "max_depth": 5, "min_samples_leaf": 20},
                {"max_iter": 100, "learning_rate": 0.05, "max_depth": 6, "min_samples_leaf": 15},
            )
        else:
            self.candidate_params = tuple(candidate_params)
            
        self.scaler: RobustScaler = RobustScaler()
        self.models: list[HistGradientBoostingRegressor] = []
        self.residual_lower_90: np.ndarray | None = None
        self.residual_upper_90: np.ndarray | None = None
        self.selected_hyperparameters: dict[str, Any] = {}
        
    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        scales: RobustScaleStatistics | None = None,
    ) -> GBDTLearnedModelV2:
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        n_features = y_train.shape[1]
        scale_vec = scales.effective_scales if scales is not None else np.ones(n_features)
        
        best_models = []
        best_param_list = []
        val_preds = np.zeros_like(y_val)
        
        for j in range(n_features):
            feat_best_param = self.candidate_params[0]
            feat_best_mae = float("inf")
            feat_best_model = None
            
            for params in self.candidate_params:
                gbr = HistGradientBoostingRegressor(
                    max_iter=params["max_iter"],
                    learning_rate=params["learning_rate"],
                    max_depth=params["max_depth"],
                    min_samples_leaf=params["min_samples_leaf"],
                    random_state=42,
                )
                gbr.fit(X_train_scaled, y_train[:, j])
                p_val = gbr.predict(X_val_scaled)
                mae = float(np.mean(np.abs(p_val - y_val[:, j])))
                if mae < feat_best_mae:
                    feat_best_mae = mae
                    feat_best_param = params
                    feat_best_model = gbr
                    
            best_models.append(feat_best_model)
            best_param_list.append(feat_best_param)
            val_preds[:, j] = feat_best_model.predict(X_val_scaled)
            
        self.models = best_models
        
        train_preds = np.zeros_like(y_train)
        for j in range(n_features):
            train_preds[:, j] = self.models[j].predict(X_train_scaled)
        train_residuals = y_train - train_preds
        self.residual_lower_90 = np.percentile(train_residuals, 5.0, axis=0)
        self.residual_upper_90 = np.percentile(train_residuals, 95.0, axis=0)
        
        norm_err = np.abs(val_preds - y_val) / scale_vec
        self.selected_hyperparameters = {
            "per_feature_params": {scales.feature_names[j]: best_param_list[j] for j in range(n_features)} if scales else best_param_list,
            "val_norm_mae": float(np.mean(norm_err)),
        }
        return self
        
    def predict(self, X: np.ndarray, X_deltas: np.ndarray | None = None, n_features: int = 15) -> np.ndarray:
        X_scaled = self.scaler.transform(X)
        preds = np.zeros((X.shape[0], n_features), dtype=np.float64)
        for j in range(n_features):
            preds[:, j] = self.models[j].predict(X_scaled)
        return preds
        
    def predict_with_interval(self, X: np.ndarray, n_features: int = 15) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        preds = self.predict(X, n_features=n_features)
        lower = preds + self.residual_lower_90
        upper = preds + self.residual_upper_90
        return preds, lower, upper
