"""Baseline ladder models B1 through B6 for Delta-State forecasting."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import numpy as np
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.linear_model import LinearRegression, Ridge
from sklearn.preprocessing import RobustScaler


@dataclass
class BaselineModelResult:
    """Evaluation result bundle for a fitted baseline model."""
    model_name: str
    model_family: str
    selected_hyperparameters: dict[str, Any]
    predictions: np.ndarray             # Shape: (N, n_features)
    lower_90: np.ndarray | None = None  # Shape: (N, n_features) if interval available
    upper_90: np.ndarray | None = None  # Shape: (N, n_features) if interval available


class ZeroChangeBaseline:
    """B1. Zero-Change: Predicts ΔS_hat = 0."""
    def __init__(self) -> None:
        self.model_name = "B1_ZeroChange"
        self.model_family = "ZeroChange"
        self.selected_hyperparameters: dict[str, Any] = {}
        
    def fit(self, X_train: np.ndarray, y_train: np.ndarray, X_val: np.ndarray | None = None, y_val: np.ndarray | None = None) -> ZeroChangeBaseline:
        return self
        
    def predict(self, X: np.ndarray, X_deltas: np.ndarray | None = None, n_features: int = 15) -> np.ndarray:
        return np.zeros((X.shape[0], n_features), dtype=np.float64)


class PersistenceBaseline:
    """
    B2. Persistence in Delta space: Predicts ΔS_hat_t = ΔS_{t-1} = S_t - S_{t-1}.
    Uses the most recent historical delta transition from the history sequence.
    """
    def __init__(self) -> None:
        self.model_name = "B2_Persistence"
        self.model_family = "Persistence"
        self.selected_hyperparameters: dict[str, Any] = {}
        
    def fit(self, X_train: np.ndarray, y_train: np.ndarray, X_val: np.ndarray | None = None, y_val: np.ndarray | None = None) -> PersistenceBaseline:
        return self
        
    def predict(self, X: np.ndarray, X_deltas: np.ndarray, n_features: int = 15) -> np.ndarray:
        # X_deltas holds [ΔS_{t-h+1}, ..., ΔS_{t-1}]
        # The most recent historical delta ΔS_{t-1} is the last n_features elements of X_deltas
        if X_deltas.shape[1] < n_features:
            return np.zeros((X.shape[0], n_features), dtype=np.float64)
        return X_deltas[:, -n_features:].copy()


class EWMABaseline:
    """
    B3. EWMA Baseline: Exponentially weighted moving average of historical deltas.
    α ∈ {0.1, 0.3, 0.5} selected strictly on validation split.
    """
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
            
        # Lags are ordered from oldest (k=n_lags-1) to newest (k=0, which is ΔS_{t-1})
        # Weight for lag from newest: w_k = alpha * (1 - alpha)^k
        preds = np.zeros((n_samples, n_features), dtype=np.float64)
        weights = []
        for lag_idx in range(n_lags):
            k = (n_lags - 1) - lag_idx  # 0 for newest, n_lags-1 for oldest
            w = alpha * ((1.0 - alpha) ** k)
            weights.append(w)
            lag_slice = X_deltas[:, lag_idx * n_features : (lag_idx + 1) * n_features]
            preds += w * lag_slice
        sum_w = sum(weights)
        if sum_w > 0:
            preds /= sum_w
        return preds
        
    def fit(self, X_train: np.ndarray, y_train: np.ndarray, X_deltas_train: np.ndarray, X_val: np.ndarray, y_val: np.ndarray, X_deltas_val: np.ndarray) -> EWMABaseline:
        n_features = y_train.shape[1]
        best_alpha = self.candidate_alphas[0]
        best_mae = float("inf")
        
        for alpha in self.candidate_alphas:
            preds_val = self._compute_ewma(X_deltas_val, alpha, n_features)
            mae = float(np.mean(np.abs(preds_val - y_val)))
            if mae < best_mae:
                best_mae = mae
                best_alpha = alpha
                
        self.selected_alpha = best_alpha
        self.selected_hyperparameters = {"alpha": self.selected_alpha, "val_mae": best_mae}
        return self
        
    def predict(self, X: np.ndarray, X_deltas: np.ndarray, n_features: int = 15) -> np.ndarray:
        return self._compute_ewma(X_deltas, self.selected_alpha, n_features)


class ARStyleBaseline:
    """
    B4. AR-style Baseline: Autoregressive model on historical deltas.
    p ∈ {1, 2, 3} (bounded by available history depth) selected strictly on validation split.
    """
    def __init__(self, candidate_p: Sequence[int] = (1, 2, 3)) -> None:
        self.model_name = "B4_AR_style"
        self.model_family = "AR-style"
        self.candidate_p = tuple(candidate_p)
        self.selected_p: int = 1
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
    ) -> ARStyleBaseline:
        n_features = y_train.shape[1]
        max_available_p = X_deltas_train.shape[1] // n_features
        valid_candidates = [p for p in self.candidate_p if 1 <= p <= max_available_p]
        if not valid_candidates:
            valid_candidates = [1]
            
        best_p = valid_candidates[0]
        best_mae = float("inf")
        best_models: list[LinearRegression] = []
        
        for p in valid_candidates:
            # Extract the most recent p lags from X_deltas
            # Lags are in X_deltas[:, -p * n_features :]
            p_train = X_deltas_train[:, -p * n_features :]
            p_val = X_deltas_val[:, -p * n_features :]
            
            # Fit per-feature AR model
            models = []
            val_preds = np.zeros_like(y_val)
            for j in range(n_features):
                # Feature j's lags across the p historical deltas
                lag_indices = [k * n_features + j for k in range(p)]
                feat_X_train = p_train[:, lag_indices]
                feat_X_val = p_val[:, lag_indices]
                
                reg = LinearRegression()
                reg.fit(feat_X_train, y_train[:, j])
                models.append(reg)
                val_preds[:, j] = reg.predict(feat_X_val)
                
            mae = float(np.mean(np.abs(val_preds - y_val)))
            if mae < best_mae:
                best_mae = mae
                best_p = p
                best_models = models
                
        self.selected_p = best_p
        self.models = best_models
        self.selected_hyperparameters = {"p": self.selected_p, "val_mae": best_mae}
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


class RidgeLearnedModel:
    """
    B5. Ridge Regression: Learned linear mapping from scaled history features to ΔS.
    Regularization alpha tuned strictly on validation split.
    """
    def __init__(self, candidate_alphas: Sequence[float] = (0.01, 0.1, 1.0, 10.0, 100.0, 1000.0)) -> None:
        self.model_name = "B5_Ridge"
        self.model_family = "Ridge"
        self.candidate_alphas = tuple(candidate_alphas)
        self.selected_alpha: float = 1.0
        self.scaler: RobustScaler = RobustScaler()
        self.model: Ridge = Ridge(alpha=1.0)
        self.residual_lower_90: np.ndarray | None = None
        self.residual_upper_90: np.ndarray | None = None
        self.selected_hyperparameters: dict[str, Any] = {}
        
    def fit(self, X_train: np.ndarray, y_train: np.ndarray, X_val: np.ndarray, y_val: np.ndarray) -> RidgeLearnedModel:
        # Fit scaler ONLY on train X
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        best_alpha = self.candidate_alphas[0]
        best_mae = float("inf")
        
        for alpha in self.candidate_alphas:
            reg = Ridge(alpha=alpha, random_state=42)
            reg.fit(X_train_scaled, y_train)
            preds_val = reg.predict(X_val_scaled)
            mae = float(np.mean(np.abs(preds_val - y_val)))
            if mae < best_mae:
                best_mae = mae
                best_alpha = alpha
                
        self.selected_alpha = best_alpha
        self.model = Ridge(alpha=self.selected_alpha, random_state=42)
        self.model.fit(X_train_scaled, y_train)
        
        # Calculate 90% empirical residual intervals from training predictions
        train_preds = self.model.predict(X_train_scaled)
        train_residuals = y_train - train_preds
        self.residual_lower_90 = np.percentile(train_residuals, 5.0, axis=0)
        self.residual_upper_90 = np.percentile(train_residuals, 95.0, axis=0)
        
        self.selected_hyperparameters = {"alpha": self.selected_alpha, "val_mae": best_mae}
        return self
        
    def predict(self, X: np.ndarray, X_deltas: np.ndarray | None = None, n_features: int = 15) -> np.ndarray:
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
        
    def predict_with_interval(self, X: np.ndarray, n_features: int = 15) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        preds = self.predict(X, n_features=n_features)
        lower = preds + self.residual_lower_90
        upper = preds + self.residual_upper_90
        return preds, lower, upper


class GBDTLearnedModel:
    """
    B6. GBDT (Gradient Boosted Decision Trees): Learned nonlinear mapping from scaled history to ΔS.
    Per-feature HistGradientBoostingRegressor tuned on validation split.
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
        
    def fit(self, X_train: np.ndarray, y_train: np.ndarray, X_val: np.ndarray, y_val: np.ndarray) -> GBDTLearnedModel:
        # Fit scaler ONLY on train X
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        n_features = y_train.shape[1]
        
        best_param = self.candidate_params[0]
        best_mae = float("inf")
        best_models: list[HistGradientBoostingRegressor] = []
        
        for params in self.candidate_params:
            models = []
            val_preds = np.zeros_like(y_val)
            for j in range(n_features):
                gbr = HistGradientBoostingRegressor(
                    max_iter=params["max_iter"],
                    learning_rate=params["learning_rate"],
                    max_depth=params["max_depth"],
                    min_samples_leaf=params["min_samples_leaf"],
                    random_state=42,
                )
                gbr.fit(X_train_scaled, y_train[:, j])
                models.append(gbr)
                val_preds[:, j] = gbr.predict(X_val_scaled)
                
            mae = float(np.mean(np.abs(val_preds - y_val)))
            if mae < best_mae:
                best_mae = mae
                best_param = params
                best_models = models
                
        self.models = best_models
        
        # Calculate 90% empirical residual intervals from training predictions
        train_preds = np.zeros_like(y_train)
        for j in range(n_features):
            train_preds[:, j] = self.models[j].predict(X_train_scaled)
        train_residuals = y_train - train_preds
        self.residual_lower_90 = np.percentile(train_residuals, 5.0, axis=0)
        self.residual_upper_90 = np.percentile(train_residuals, 95.0, axis=0)
        
        self.selected_hyperparameters = {**best_param, "val_mae": best_mae}
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
