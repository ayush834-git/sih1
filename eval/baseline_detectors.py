"""Baseline Current-State Detector, Logistic Regression Benchmark, and Predictive Detector (SIH 26153)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.preprocessing import StandardScaler

from core.contracts import NetworkState, TrustLevel
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.models_v2 import ARStyleBaselineV2
from eval.rollout import MultiStepRolloutEngine


@dataclass(frozen=True)
class DetectionResult:
    """Standardized detection result for a single evaluation window."""
    is_alert: bool
    event_type: str
    confidence: float
    trigger_reason: str
    feature_values: dict[str, float]


class ConventionalCurrentStateDetector:
    """
    Conventional current-state threshold detector using ONLY current observed NetworkState.
    No future state, forecast, attack labels, or future-derived rolling statistics.
    """
    def __init__(
        self,
        recon_port_thresh: int = 20,
        dos_flow_thresh: int = 200,
        dos_rst_thresh: float = 0.25,
        exfil_byte_thresh: float = 100000.0,
    ) -> None:
        self.recon_port_thresh = recon_port_thresh
        self.dos_flow_thresh = dos_flow_thresh
        self.dos_rst_thresh = dos_rst_thresh
        self.exfil_byte_thresh = exfil_byte_thresh

    def evaluate_state(self, state: NetworkState) -> DetectionResult:
        vals = state.feature_values()
        port_div = vals.get("dst_port_diversity") or 0
        flow_cnt = vals.get("flow_count") or 0
        rst_ratio = vals.get("rst_ratio") or 0.0
        byte_rate = vals.get("byte_rate") or 0.0

        if port_div >= self.recon_port_thresh:
            return DetectionResult(
                is_alert=True,
                event_type="Reconnaissance",
                confidence=min(1.0, 0.5 + (port_div / (2 * self.recon_port_thresh))),
                trigger_reason=f"Current dst_port_diversity={port_div} >= {self.recon_port_thresh}",
                feature_values=vals,
            )
        elif flow_cnt >= self.dos_flow_thresh and rst_ratio >= self.dos_rst_thresh:
            return DetectionResult(
                is_alert=True,
                event_type="Impact / Denial of Service",
                confidence=0.75,
                trigger_reason=f"Current flow_count={flow_cnt} >= {self.dos_flow_thresh} and rst_ratio={rst_ratio:.2f} >= {self.dos_rst_thresh}",
                feature_values=vals,
            )
        elif byte_rate >= self.exfil_byte_thresh:
            return DetectionResult(
                is_alert=True,
                event_type="Collection / Exfiltration",
                confidence=0.70,
                trigger_reason=f"Current byte_rate={byte_rate:,.0f} >= {self.exfil_byte_thresh:,.0f}",
                feature_values=vals,
            )
        else:
            return DetectionResult(
                is_alert=False,
                event_type="None",
                confidence=0.10,
                trigger_reason="Telemetry within normal baseline thresholds",
                feature_values=vals,
            )


class LogisticRegressionBaselineDetector:
    """
    Supervised Logistic Regression baseline trained on chronological training data.
    """
    def __init__(self, feature_names: Sequence[str] = CSV_AVAILABLE_FEATURES, threshold: float = 0.50) -> None:
        self.feature_names = list(feature_names)
        self.threshold = threshold
        self.scaler = StandardScaler()
        self.model = LogisticRegression(class_weight="balanced", random_state=42, max_iter=1000)
        self.is_fitted = False

    def fit(self, X_train: np.ndarray, y_train: np.ndarray) -> LogisticRegressionBaselineDetector:
        X_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_scaled, y_train)
        self.is_fitted = True
        return self

    def evaluate_state(self, state: NetworkState) -> DetectionResult:
        if not self.is_fitted:
            # Fallback heuristic if not explicitly trained
            vals = state.feature_values()
            p = 0.85 if (vals.get("dst_port_diversity") or 0) >= 20 else 0.05
        else:
            vals = state.feature_values()
            x = np.array([[vals.get(f, 0.0) or 0.0 for f in self.feature_names]])
            x_scaled = self.scaler.transform(x)
            p = float(self.model.predict_proba(x_scaled)[0, 1])

        is_alert = p >= self.threshold
        return DetectionResult(
            is_alert=is_alert,
            event_type="SecurityEvent" if is_alert else "None",
            confidence=p,
            trigger_reason=f"Logistic Regression P(Event)={p:.3f} (Threshold={self.threshold})",
            feature_values=state.feature_values(),
        )


class PredictiveTrajectoryDetector:
    """
    Predictive detector evaluating current state + AR(5) multi-step forecast trajectory.
    Triggers when future trajectory projects crossing security thresholds within horizons h=1..3.
    """
    def __init__(
        self,
        rollout_engine: MultiStepRolloutEngine,
        feature_names: Sequence[str] = CSV_AVAILABLE_FEATURES,
        recon_port_thresh: int = 20,
        dos_flow_thresh: int = 200,
        exfil_byte_thresh: float = 100000.0,
    ) -> None:
        self.rollout_engine = rollout_engine
        self.feature_names = list(feature_names)
        self.recon_port_thresh = recon_port_thresh
        self.dos_flow_thresh = dos_flow_thresh
        self.exfil_byte_thresh = exfil_byte_thresh

    def evaluate_state_and_forecast(
        self,
        current_state: NetworkState,
        predicted_deltas: np.ndarray,  # Shape: (max_horizon, n_feats)
        trust_level: TrustLevel = TrustLevel.HIGH,
    ) -> DetectionResult:
        """
        Evaluate whether the multi-step trajectory projects crossing event thresholds.
        """
        vals = current_state.feature_values()
        n_feats = len(self.feature_names)
        port_idx = self.feature_names.index("dst_port_diversity")
        flow_idx = self.feature_names.index("flow_count")
        byte_idx = self.feature_names.index("byte_rate")
        
        cur_port = vals.get("dst_port_diversity") or 0.0
        cur_flow = vals.get("flow_count") or 0.0
        cur_byte = vals.get("byte_rate") or 0.0

        # Project cumulative states across horizon h=1..3
        cum_port = cur_port
        cum_flow = cur_flow
        cum_byte = cur_byte
        
        predicted_event = None
        predicted_horizon = None

        for h in range(predicted_deltas.shape[0]):
            cum_port += predicted_deltas[h, port_idx]
            cum_flow += predicted_deltas[h, flow_idx]
            cum_byte += predicted_deltas[h, byte_idx]

            # Predictive alert conditions with trust guard
            if cum_port >= self.recon_port_thresh and trust_level in (TrustLevel.HIGH, TrustLevel.MEDIUM):
                predicted_event = "Reconnaissance"
                predicted_horizon = h + 1
                break
            elif cum_flow >= self.dos_flow_thresh and trust_level in (TrustLevel.HIGH, TrustLevel.MEDIUM):
                predicted_event = "Impact / Denial of Service"
                predicted_horizon = h + 1
                break
            elif cum_byte >= self.exfil_byte_thresh and trust_level in (TrustLevel.HIGH, TrustLevel.MEDIUM):
                predicted_event = "Collection / Exfiltration"
                predicted_horizon = h + 1
                break

        # Fallback to current state alert if current state is already elevated
        if predicted_event is None:
            if cur_port >= self.recon_port_thresh:
                predicted_event = "Reconnaissance"
                predicted_horizon = 0
            elif cur_flow >= self.dos_flow_thresh:
                predicted_event = "Impact / Denial of Service"
                predicted_horizon = 0
            elif cur_byte >= self.exfil_byte_thresh:
                predicted_event = "Collection / Exfiltration"
                predicted_horizon = 0

        if predicted_event is not None:
            horizon_desc = f"at h={predicted_horizon}" if predicted_horizon > 0 else "at current state"
            return DetectionResult(
                is_alert=True,
                event_type=predicted_event,
                confidence=0.80 if trust_level == TrustLevel.HIGH else 0.60,
                trigger_reason=f"Trajectory forecast predicts {predicted_event} condition {horizon_desc} (Trust={trust_level.value})",
                feature_values=vals,
            )
        else:
            return DetectionResult(
                is_alert=False,
                event_type="None",
                confidence=0.15,
                trigger_reason="Forecast projects state remaining within normal boundaries",
                feature_values=vals,
            )
