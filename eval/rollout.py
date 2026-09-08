"""Multi-Step Rollout, Residual Bootstrap Uncertainty, and Multi-Future Trajectory Engine."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence

import numpy as np

from core.contracts import (
    STATE_SCHEMA_HASH,
    FeatureAvailability,
    Forecast,
    NetworkState,
    Source,
    Trajectory,
    TrajectoryStep,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    Direction,
    new_id,
)
from eval.dataset import (
    CSV_AVAILABLE_FEATURES,
    OBSERVED_INFILTRATION_BLOCKS,
    load_states_from_jsonl,
)
from eval.metrics_v2 import RobustScaleStatistics, compute_training_scales
from eval.models_v2 import ARStyleBaselineV2


@dataclass(frozen=True)
class MultiStepSample:
    """A sample supporting multi-step evaluation up to max_horizon."""
    sample_id: str
    source_state: NetworkState
    source_time: datetime
    target_start: datetime
    target_end: datetime
    session_id: str
    history_states: tuple[dict[str, float], ...]  # S_{t-5} ... S_t (length 6)
    history_deltas: tuple[dict[str, float], ...]  # ΔS_{t-5} ... ΔS_{t-1} (length 5)
    future_states: tuple[dict[str, float], ...]   # S_{t+1}, S_{t+2}, S_{t+3} (length max_horizon)
    future_deltas: tuple[dict[str, float], ...]   # ΔS_{t+1}, ΔS_{t+2}, ΔS_{t+3} (length max_horizon)
    feature_names: tuple[str, ...]


def extract_multistep_samples(
    states: Sequence[NetworkState],
    history_depth: int = 6,
    max_horizon: int = 3,
    feature_names: Sequence[str] | None = None,
) -> tuple[list[MultiStepSample], dict[str, int]]:
    """
    Extract contiguous state windows of length (history_depth + max_horizon):
    [S_{t-h+1}, ..., S_t, S_{t+1}, ..., S_{t+H}]
    ensuring strict within-session continuity without gaps or empty states.
    """
    if feature_names is None:
        feature_names = tuple(CSV_AVAILABLE_FEATURES)
    else:
        feature_names = tuple(feature_names)
        
    window_len = history_depth + max_horizon
    samples: list[MultiStepSample] = []
    dropped: dict[str, int] = {
        "empty_state_in_window": 0,
        "session_boundary_crossed": 0,
        "time_gap_encountered": 0,
        "unavailable_feature": 0,
    }
    
    for i in range(len(states) - window_len + 1):
        window = states[i : i + window_len]
        
        # Check empty states
        if any(s.is_empty for s in window):
            dropped["empty_state_in_window"] += 1
            continue
            
        # Check session consistency
        sessions = {s.session_id for s in window}
        if len(sessions) > 1:
            dropped["session_boundary_crossed"] += 1
            continue
            
        # Check time continuity (exact window duration increments)
        time_valid = True
        for k in range(len(window) - 1):
            if window[k].timestamp_end != window[k + 1].timestamp_start:
                time_valid = False
                break
        if not time_valid:
            dropped["time_gap_encountered"] += 1
            continue
            
        # Extract features
        feat_valid = True
        f_dicts = []
        for s in window:
            fvals = s.feature_values()
            if not all(f in fvals for f in feature_names):
                feat_valid = False
                break
            f_dicts.append({f: fvals[f] for f in feature_names})
        if not feat_valid:
            dropped["unavailable_feature"] += 1
            continue
            
        h_states = tuple(f_dicts[:history_depth])
        f_states = tuple(f_dicts[history_depth:])
        
        # Historical deltas: ΔS_{t-h+1} .. ΔS_{t-1} (length history_depth - 1)
        h_deltas = tuple(
            {f: h_states[k + 1][f] - h_states[k][f] for f in feature_names}
            for k in range(len(h_states) - 1)
        )
        
        # Future deltas: ΔS_{t+1} = S_{t+1} - S_t, ΔS_{t+2} = S_{t+2} - S_{t+1}, etc.
        all_future_sequence = (h_states[-1],) + f_states
        f_deltas = tuple(
            {f: all_future_sequence[k + 1][f] - all_future_sequence[k][f] for f in feature_names}
            for k in range(max_horizon)
        )
        
        src_state = window[history_depth - 1]
        target_state = window[history_depth]
        sample = MultiStepSample(
            sample_id=f"rollout_{src_state.window_id}",
            source_state=src_state,
            source_time=src_state.timestamp_start,
            target_start=target_state.timestamp_start,
            target_end=target_state.timestamp_end,
            session_id=src_state.session_id,
            history_states=h_states,
            history_deltas=h_deltas,
            future_states=f_states,
            future_deltas=f_deltas,
            feature_names=feature_names,
        )
        samples.append(sample)
        
    return samples, dropped


class MultiStepRolloutEngine:
    """Executes open-loop recursive rollout and receding-horizon rollout."""
    def __init__(self, ar_model: ARStyleBaselineV2, feature_names: Sequence[str]) -> None:
        self.ar_model = ar_model
        self.feature_names = list(feature_names)
        self.n_features = len(self.feature_names)
        
    def forecast_open_loop(
        self,
        history_deltas: np.ndarray,  # Shape: (N, 5 * n_features)
        current_states: np.ndarray,  # Shape: (N, n_features)
        max_horizon: int = 3,
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Open-loop recursive rollout for h=1..max_horizon.
        Returns:
        - predicted_deltas: Shape (N, max_horizon, n_features)
        - predicted_states: Shape (N, max_horizon, n_features)
        Strictly zero access to future ground truth.
        """
        n_samples = history_deltas.shape[0]
        pred_deltas = np.zeros((n_samples, max_horizon, self.n_features), dtype=np.float64)
        pred_states = np.zeros((n_samples, max_horizon, self.n_features), dtype=np.float64)
        
        # Working buffer of past deltas: starts with [ΔS_{t-4}, ..., ΔS_t]
        p = self.ar_model.selected_p
        curr_delta_buffer = history_deltas[:, -p * self.n_features :].copy()
        curr_state = current_states.copy()
        
        for h in range(max_horizon):
            # Predict step h+1 using current delta buffer
            step_pred_delta = np.zeros((n_samples, self.n_features), dtype=np.float64)
            for j in range(self.n_features):
                lag_indices = [k * self.n_features + j for k in range(p)]
                feat_X = curr_delta_buffer[:, lag_indices]
                step_pred_delta[:, j] = self.ar_model.models[j].predict(feat_X)
                
            pred_deltas[:, h, :] = step_pred_delta
            curr_state = curr_state + step_pred_delta
            pred_states[:, h, :] = curr_state
            
            # Update delta buffer: slide left and append newly predicted delta at right
            if p > 1:
                curr_delta_buffer = np.hstack([curr_delta_buffer[:, self.n_features :], step_pred_delta])
            else:
                curr_delta_buffer = step_pred_delta.copy()
                
        return pred_deltas, pred_states

    def forecast_receding_horizon(
        self,
        samples: list[MultiStepSample],
        max_horizon: int = 3,
    ) -> np.ndarray:
        """
        Receding-horizon rollout: at each step k in 1..H, the model forecasts
        1 step ahead with newly observed true state context refreshed.
        Returns predicted_deltas: Shape (N, max_horizon, n_features)
        """
        n_samples = len(samples)
        pred_deltas = np.zeros((n_samples, max_horizon, self.n_features), dtype=np.float64)
        p = self.ar_model.selected_p
        
        for i, s in enumerate(samples):
            # Sequence of available ground-truth historical deltas up to each horizon
            all_deltas = list(s.history_deltas)
            for h in range(max_horizon):
                # When forecasting step h+1, we have observed all deltas up to step h
                recent_p_deltas = all_deltas[-p:]
                feat_vec = []
                for d_dict in recent_p_deltas:
                    for f in self.feature_names:
                        feat_vec.append(d_dict[f])
                feat_arr = np.array(feat_vec, dtype=np.float64).reshape(1, -1)
                
                step_pred = np.zeros(self.n_features, dtype=np.float64)
                for j in range(self.n_features):
                    lag_indices = [k * self.n_features + j for k in range(p)]
                    step_pred[j] = self.ar_model.models[j].predict(feat_arr[:, lag_indices])[0]
                    
                pred_deltas[i, h, :] = step_pred
                # In receding horizon, the true observed delta at step h+1 is added for subsequent step
                if h < len(s.future_deltas):
                    all_deltas.append(s.future_deltas[h])
                    
        return pred_deltas


class ResidualBootstrapEngine:
    """
    Residual Bootstrap Uncertainty Quantification.
    Samples joint residual vectors exclusively from training residuals
    to preserve cross-feature correlation.
    """
    def __init__(self, y_train: np.ndarray, y_train_pred: np.ndarray, seed: int = 42) -> None:
        self.residuals = y_train - y_train_pred  # Shape: (N_train, D)
        self.n_pool = self.residuals.shape[0]
        self.n_features = self.residuals.shape[1]
        self.rng = np.random.default_rng(seed)
        
    def generate_bootstrap_rollouts(
        self,
        ar_model: ARStyleBaselineV2,
        history_deltas: np.ndarray,  # Shape: (N, 5 * n_features)
        current_states: np.ndarray,  # Shape: (N, n_features)
        n_bootstrap: int = 100,
        max_horizon: int = 3,
    ) -> np.ndarray:
        """
        Generate B bootstrap recursive trajectory paths for each test sample.
        Returns array of shape: (N, B, max_horizon, n_features)
        """
        n_samples = history_deltas.shape[0]
        p = ar_model.selected_p
        bootstrap_deltas = np.zeros((n_samples, n_bootstrap, max_horizon, self.n_features), dtype=np.float64)
        
        for b in range(n_bootstrap):
            curr_delta_buffer = history_deltas[:, -p * self.n_features :].copy()
            
            for h in range(max_horizon):
                # Deterministic prediction
                step_pred = np.zeros((n_samples, self.n_features), dtype=np.float64)
                for j in range(self.n_features):
                    lag_indices = [k * self.n_features + j for k in range(p)]
                    step_pred[:, j] = ar_model.models[j].predict(curr_delta_buffer[:, lag_indices])
                    
                # Sample joint residual vectors with replacement from training residual pool
                res_indices = self.rng.integers(0, self.n_pool, size=n_samples)
                sampled_res = self.residuals[res_indices, :]
                
                sim_delta = step_pred + sampled_res
                bootstrap_deltas[:, b, h, :] = sim_delta
                
                # Recursive update with simulated delta
                if p > 1:
                    curr_delta_buffer = np.hstack([curr_delta_buffer[:, self.n_features :], sim_delta])
                else:
                    curr_delta_buffer = sim_delta.copy()
                    
        return bootstrap_deltas

    def compute_prediction_intervals(
        self,
        bootstrap_deltas: np.ndarray,  # Shape: (N, B, max_horizon, n_features)
        nominal_levels: Sequence[float] = (0.80, 0.90, 0.95),
    ) -> dict[float, tuple[np.ndarray, np.ndarray]]:
        """
        Compute empirical lower and upper quantile bounds for each nominal level.
        Returns dict mapping nominal_level -> (lower_bounds, upper_bounds)
        where bounds have shape (N, max_horizon, n_features).
        """
        intervals: dict[float, tuple[np.ndarray, np.ndarray]] = {}
        for level in nominal_levels:
            alpha = 1.0 - level
            lower_q = (alpha / 2.0) * 100.0
            upper_q = (1.0 - alpha / 2.0) * 100.0
            
            lower_b = np.percentile(bootstrap_deltas, lower_q, axis=1)
            upper_b = np.percentile(bootstrap_deltas, upper_q, axis=1)
            intervals[level] = (lower_b, upper_b)
            
        return intervals


class MultiFutureTrajectoryGenerator:
    """Generates K=3 defensible candidate futures conforming to core/contracts.py from actual bootstrap paths."""
    def __init__(self, feature_names: Sequence[str], model_id: str = "AR_p5_Bootstrap", scales: RobustScaleStatistics | None = None) -> None:
        self.feature_names = list(feature_names)
        self.model_id = model_id
        self.scales = scales
        
    def construct_k3_trajectories(
        self,
        sample: MultiStepSample,
        det_deltas: np.ndarray,       # Shape: (max_horizon, n_features)
        bootstrap_deltas: np.ndarray, # Shape: (B, max_horizon, n_features)
        current_time: datetime,
    ) -> tuple[Trajectory, Trajectory, Trajectory]:
        """
        Construct K=3 candidate trajectories from actual simulation paths:
        - T0: Deterministic AR path (Scenario-Display Weight = 0.50)
        - T1: Actual Empirical Upper Bootstrap path closest to 75th percentile deviation (Weight = 0.25)
        - T2: Actual Empirical Lower Bootstrap path closest to 25th percentile deviation (Weight = 0.25)
        Preserves cross-feature and cross-horizon correlation by using one continuous bootstrap path per trajectory.
        """
        max_horizon = det_deltas.shape[0]
        n_bootstrap = bootstrap_deltas.shape[0]
        src = sample.source_state
        src_vals = src.feature_values()
        
        # 1. Deterministic path (T0)
        t0_steps = []
        curr_state_0 = dict(src_vals)
        for h in range(max_horizon):
            step_delta = {f: float(det_deltas[h, j]) for j, f in enumerate(self.feature_names)}
            step_state = {f: curr_state_0[f] + step_delta[f] for f in self.feature_names}
            fc = Forecast(
                forecast_id=new_id("fc-det"),
                source_state_id=src.window_id,
                target_timestamp=src.timestamp_end + timedelta(seconds=10 * (h + 1)),
                horizon_steps=h + 1,
                delta_predicted=step_delta,
                state_predicted=step_state,
                model_id=self.model_id,
                model_version="day5-v1-corrected",
                feature_schema_hash=STATE_SCHEMA_HASH,
                created_at=current_time,
            )
            t0_steps.append(TrajectoryStep(step_index=h, forecast=fc))
            curr_state_0 = step_state
            
        t0 = Trajectory(
            trajectory_id=new_id("traj-0-deterministic"),
            parent_state_id=src.window_id,
            steps=t0_steps,
            weight=0.50,
            cumulative_error=None,
            is_active=True,
            pruned_reason=None,
            created_at=current_time,
            last_updated=current_time,
        )
        
        # Compute trajectory-level normalized deviation score for each actual bootstrap path
        scale_vec = self.scales.effective_scales if self.scales is not None else np.ones(len(self.feature_names))
        # dev_scores: shape (B,)
        norm_diff = (bootstrap_deltas - det_deltas[np.newaxis, :, :]) / scale_vec[np.newaxis, np.newaxis, :]
        traj_deviations = np.mean(norm_diff, axis=(1, 2))  # Mean over horizon and features
        
        sorted_indices = np.argsort(traj_deviations)
        # Select single actual continuous bootstrap trajectory indices
        idx_upper = sorted_indices[int(round(0.75 * (n_bootstrap - 1)))]
        idx_lower = sorted_indices[int(round(0.25 * (n_bootstrap - 1)))]
        
        upper_path = bootstrap_deltas[idx_upper]  # Shape: (max_horizon, n_features)
        lower_path = bootstrap_deltas[idx_lower]  # Shape: (max_horizon, n_features)
        
        # 2. Actual Empirical Upper Trajectory (T1)
        t1_steps = []
        curr_state_1 = dict(src_vals)
        for h in range(max_horizon):
            step_delta = {f: float(upper_path[h, j]) for j, f in enumerate(self.feature_names)}
            step_state = {f: curr_state_1[f] + step_delta[f] for f in self.feature_names}
            fc = Forecast(
                forecast_id=new_id("fc-emp-upper"),
                source_state_id=src.window_id,
                target_timestamp=src.timestamp_end + timedelta(seconds=10 * (h + 1)),
                horizon_steps=h + 1,
                delta_predicted=step_delta,
                state_predicted=step_state,
                model_id=self.model_id,
                model_version="day5-v1-corrected",
                feature_schema_hash=STATE_SCHEMA_HASH,
                created_at=current_time,
            )
            t1_steps.append(TrajectoryStep(step_index=h, forecast=fc))
            curr_state_1 = step_state
            
        t1 = Trajectory(
            trajectory_id=new_id("traj-1-empirical-upper"),
            parent_state_id=src.window_id,
            steps=t1_steps,
            weight=0.25,
            cumulative_error=None,
            is_active=True,
            pruned_reason=None,
            created_at=current_time,
            last_updated=current_time,
        )
        
        # 3. Actual Empirical Lower Trajectory (T2)
        t2_steps = []
        curr_state_2 = dict(src_vals)
        for h in range(max_horizon):
            step_delta = {f: float(lower_path[h, j]) for j, f in enumerate(self.feature_names)}
            step_state = {f: curr_state_2[f] + step_delta[f] for f in self.feature_names}
            fc = Forecast(
                forecast_id=new_id("fc-emp-lower"),
                source_state_id=src.window_id,
                target_timestamp=src.timestamp_end + timedelta(seconds=10 * (h + 1)),
                horizon_steps=h + 1,
                delta_predicted=step_delta,
                state_predicted=step_state,
                model_id=self.model_id,
                model_version="day5-v1-corrected",
                feature_schema_hash=STATE_SCHEMA_HASH,
                created_at=current_time,
            )
            t2_steps.append(TrajectoryStep(step_index=h, forecast=fc))
            curr_state_2 = step_state
            
        t2 = Trajectory(
            trajectory_id=new_id("traj-2-empirical-lower"),
            parent_state_id=src.window_id,
            steps=t2_steps,
            weight=0.25,
            cumulative_error=None,
            is_active=True,
            pruned_reason=None,
            created_at=current_time,
            last_updated=current_time,
        )
        
        return t0, t1, t2


class TrustScoringEngine:
    """Computes forecast trust score and assesses trust degradation across horizons."""
    def __init__(self, scales: RobustScaleStatistics) -> None:
        self.scales = scales
        
    def compute_trust_for_horizon(
        self,
        horizon_step: int,
        interval_width: float,  # mean normalized interval width
        historical_error: float,
        data_quality: float = 1.0,
    ) -> TrustAssessment:
        """
        Calculates composite trust score T(h) in [0, 1].
        Trust decays with horizon step and widening uncertainty intervals.
        """
        # Horizon factor: decreases by 0.12 per step
        horizon_penalty = 0.12 * (horizon_step - 1)
        
        # Uncertainty width penalty: scaled interval width
        width_penalty = min(0.40, max(0.0, (interval_width - 1.0) * 0.10))
        
        # Historical error penalty
        err_penalty = min(0.30, max(0.0, (historical_error - 1.0) * 0.05))
        
        composite = max(0.05, min(0.95, 0.90 * data_quality - horizon_penalty - width_penalty - err_penalty))
        
        if composite >= 0.70:
            level = TrustLevel.HIGH
        elif composite >= 0.45:
            level = TrustLevel.MEDIUM
        elif composite >= 0.20:
            level = TrustLevel.LOW
        else:
            level = TrustLevel.INSUFFICIENT
            
        factors = [
            TrustFactor("horizon_step", float(horizon_step), Direction.DECREASES_TRUST if horizon_step > 1 else Direction.INCREASES_TRUST),
            TrustFactor("normalized_interval_width", float(interval_width), Direction.DECREASES_TRUST if interval_width > 2.0 else Direction.INCREASES_TRUST),
            TrustFactor("data_quality", float(data_quality), Direction.INCREASES_TRUST),
        ]
        
        return TrustAssessment(
            assessment_id=new_id("trust"),
            forecast_id=new_id("fc"),
            forecast_confidence=composite,
            model_disagreement=0.0,
            distribution_shift_score=0.0,
            novelty_score=0.0,
            historical_error=historical_error,
            data_quality=data_quality,
            composite_trust=composite,
            trust_level=level,
            contributing_factors=factors,
        )
