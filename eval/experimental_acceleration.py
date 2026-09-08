"""
Research Treatment: Second-Order Temporal Difference (Δ² / Acceleration) Detector (SIH PS 26153).

A research evaluation candidate to test whether second-order temporal change (acceleration/inflection):
    ΔS_t = S_t - S_{t-1}
    Δ²S_t = ΔS_t - ΔS_{t-1} = S_t - 2*S_{t-1} + S_{t-2}
provides earlier, actionable warning before conventional trajectory thresholds are crossed.

Strict Methodology Constraints:
1. RESEARCH TREATMENT ONLY: Baseline PredictiveTrajectoryDetector and AR(5) model remain unchanged.
2. Strictly Causal: Δ² at time t uses ONLY {S_t, S_{t-1}, S_{t-2}} (or ΔS_t, ΔS_{t-1}).
   Zero future ground truth or future trajectory observations may be accessed.
3. Trust Guard Preserved: Forecast trust/quality safeguards are strictly enforced.
4. Non-Trivial Inflection Rule: Does NOT simply fire on Δ² > 0.
   Requires:
   - Valid acceleration: Δ²S_t[f] >= theta_accel[f]
   - Positive velocity: ΔS_t[f] > 0
   - Forward AR(5) trajectory confirmation: sum_{h=1..H} ΔS_hat_{t+h}[f] > 0
   - Inflection floor: S_t[f] >= inflection_ratio * threshold[f]
   - Second-order augmented projection crossing detection threshold.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

import numpy as np

from core.contracts import NetworkState, TrustLevel
from eval.baseline_detectors import DetectionResult, PredictiveTrajectoryDetector
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.rollout import MultiStepRolloutEngine


# ─────────────────────────────────────────────────────────────────────────────
# Frozen Pre-Test Calibration Parameters (Thursday 04:00:00 to 08:00:00 UTC)
# Strictly derived prior to held-out test splits without access to attack blocks.
# ─────────────────────────────────────────────────────────────────────────────
FROZEN_CALIBRATION_METADATA = {
    "calibration_dataset": "Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl",
    "calibration_window": "2018-03-01T04:00:00Z to 2018-03-01T08:00:00Z",
    "n_calibration_windows": 625,
    "held_out_attack_blocks_accessed": False,
    "parameter_selection_method": "Empirical pre-test distribution quantile & robust dispersion",
}

# Calibrated Acceleration Thresholds (theta_accel) for standard dataset evaluation
DEFAULT_ACCEL_THRESHOLDS: dict[str, float] = {
    "dst_port_diversity": 10.0,  # Pre-test 90th percentile: 18.0, MAD=8.0; inflection floor set to 10.0
    "flow_count": 50.0,          # Pre-test 90th percentile: 111.0, MAD=35.0; inflection floor set to 50.0
    "byte_rate": 25000.0,        # Pre-test 90th percentile: 41,172.0, MAD=6,716.1; inflection floor set to 25,000.0
}


def compute_second_difference(
    states: Sequence[NetworkState],
    feature_names: Sequence[str] = CSV_AVAILABLE_FEATURES,
) -> dict[str, float] | None:
    """
    Compute strictly causal second-order temporal difference (Δ²S_t) across 3 consecutive windows:
        ΔS_t = S_t - S_{t-1}
        ΔS_{t-1} = S_{t-1} - S_{t-2}
        Δ²S_t = ΔS_t - ΔS_{t-1} = S_t - 2*S_{t-1} + S_{t-2}

    Invariants:
    - Requires len(states) >= 3.
    - Requires identical session_id across all 3 states.
    - Requires strict temporal continuity: (S_k.start - S_{k-1}.end) < 0.1s.
    - Requires strictly non-decreasing timestamps.
    - Returns None if any continuity invariant fails or history is insufficient.
    """
    if len(states) < 3:
        return None

    s_curr = states[-1]
    s_prev1 = states[-2]
    s_prev2 = states[-3]

    # Session consistency check
    if s_curr.session_id != s_prev1.session_id or s_prev1.session_id != s_prev2.session_id:
        return None

    # Temporal monotonicity and continuity check (max 0.1s tolerance for floating precision)
    gap1 = (s_curr.timestamp_start - s_prev1.timestamp_end).total_seconds()
    gap2 = (s_prev1.timestamp_start - s_prev2.timestamp_end).total_seconds()
    if abs(gap1) > 0.10 or abs(gap2) > 0.10:
        return None

    if s_curr.timestamp_start <= s_prev1.timestamp_start or s_prev1.timestamp_start <= s_prev2.timestamp_start:
        return None

    curr_vals = s_curr.feature_values()
    prev1_vals = s_prev1.feature_values()
    prev2_vals = s_prev2.feature_values()

    d2: dict[str, float] = {}
    for f in feature_names:
        v_curr = float(curr_vals.get(f, 0.0) or 0.0)
        v_prev1 = float(prev1_vals.get(f, 0.0) or 0.0)
        v_prev2 = float(prev2_vals.get(f, 0.0) or 0.0)

        # ΔS_t = v_curr - v_prev1
        # ΔS_{t-1} = v_prev1 - v_prev2
        # Δ²S_t = ΔS_t - ΔS_{t-1} = v_curr - 2 * v_prev1 + v_prev2
        d2[f] = v_curr - (2.0 * v_prev1) + v_prev2

    return d2


class AccelerationAugmentedTrajectoryDetector(PredictiveTrajectoryDetector):
    """
    Research Treatment: Predictive Trajectory Detector augmented with Δ² temporal acceleration.

    Does NOT modify or replace the baseline PredictiveTrajectoryDetector.
    Extends the decision surface with an early inflection rule:
    1. Computes Δ²S_t from trailing historical states {S_t, S_{t-1}, S_{t-2}}.
    2. Checks whether positive acceleration exceeds the calibrated noise floor:
       Δ²S_t[f] >= theta_accel[f] and ΔS_t[f] > 0.
    3. Verifies forward AR(5) forecast confirms directional expansion:
       sum_{h=1..H} ΔS_hat_{t+h}[f] > 0.
    4. Evaluates second-order Taylor projection:
       S_hat_{t+h}^accel = S_t + sum_{i=1}^h ΔS_hat_{t+i} + 0.5 * h * Δ²S_t >= threshold.
    5. Preserves strict forecast trust requirements (HIGH or MEDIUM only).
    """

    def __init__(
        self,
        rollout_engine: MultiStepRolloutEngine,
        feature_names: Sequence[str] = CSV_AVAILABLE_FEATURES,
        recon_port_thresh: int = 20,
        dos_flow_thresh: int = 200,
        exfil_byte_thresh: float = 100000.0,
        accel_port_thresh: float | None = None,
        accel_flow_thresh: float | None = None,
        accel_byte_thresh: float | None = None,
        inflection_ratio: float = 0.40,
        accel_beta: float = 0.50,
    ) -> None:
        super().__init__(
            rollout_engine=rollout_engine,
            feature_names=feature_names,
            recon_port_thresh=recon_port_thresh,
            dos_flow_thresh=dos_flow_thresh,
            exfil_byte_thresh=exfil_byte_thresh,
        )
        self.accel_port_thresh = (
            accel_port_thresh if accel_port_thresh is not None else DEFAULT_ACCEL_THRESHOLDS["dst_port_diversity"]
        )
        self.accel_flow_thresh = (
            accel_flow_thresh if accel_flow_thresh is not None else DEFAULT_ACCEL_THRESHOLDS["flow_count"]
        )
        self.accel_byte_thresh = (
            accel_byte_thresh if accel_byte_thresh is not None else DEFAULT_ACCEL_THRESHOLDS["byte_rate"]
        )
        self.inflection_ratio = float(inflection_ratio)
        self.accel_beta = float(accel_beta)

        # Internal trailing history buffer for causal online operation
        self._history_states: list[NetworkState] = []

    def reset_history(self) -> None:
        """Clear internal trailing state buffer."""
        self._history_states.clear()

    def evaluate_state_and_forecast(
        self,
        current_state: NetworkState,
        predicted_deltas: np.ndarray,  # Shape: (max_horizon, n_feats)
        trust_level: TrustLevel = TrustLevel.HIGH,
        history_states: Sequence[NetworkState] | None = None,
        history_deltas: Sequence[Mapping[str, float]] | None = None,
    ) -> DetectionResult:
        """
        Evaluate current state, forward AR(5) forecast, and second-order acceleration.
        Falls back cleanly to baseline trajectory evaluation if history is insufficient
        or continuity is broken.
        """
        # Maintain causal internal state buffer if external history not provided
        if history_states is not None:
            active_history = list(history_states)
        else:
            self._history_states.append(current_state)
            if len(self._history_states) > 10:
                self._history_states.pop(0)
            active_history = self._history_states

        # 1. Compute Δ²S_t strictly causally
        d2 = compute_second_difference(active_history, self.feature_names)

        # 2. Extract current velocity ΔS_t if available
        d1: dict[str, float] | None = None
        if len(active_history) >= 2:
            s_curr = active_history[-1]
            s_prev = active_history[-2]
            if s_curr.session_id == s_prev.session_id and abs((s_curr.timestamp_start - s_prev.timestamp_end).total_seconds()) <= 0.10:
                c_vals = s_curr.feature_values()
                p_vals = s_prev.feature_values()
                d1 = {f: float(c_vals.get(f, 0.0) or 0.0) - float(p_vals.get(f, 0.0) or 0.0) for f in self.feature_names}

        # 3. Evaluate Acceleration Inflection Alert
        # Preserves strict trust requirement: never alerts on LOW or INSUFFICIENT trust
        if d2 is not None and d1 is not None and trust_level in (TrustLevel.HIGH, TrustLevel.MEDIUM):
            vals = current_state.feature_values()
            port_idx = self.feature_names.index("dst_port_diversity")
            flow_idx = self.feature_names.index("flow_count")
            byte_idx = self.feature_names.index("byte_rate")

            cur_port = float(vals.get("dst_port_diversity") or 0.0)
            cur_flow = float(vals.get("flow_count") or 0.0)
            cur_byte = float(vals.get("byte_rate") or 0.0)

            port_accel = d2.get("dst_port_diversity", 0.0)
            flow_accel = d2.get("flow_count", 0.0)
            byte_accel = d2.get("byte_rate", 0.0)

            port_vel = d1.get("dst_port_diversity", 0.0)
            flow_vel = d1.get("flow_count", 0.0)
            byte_vel = d1.get("byte_rate", 0.0)

            # Cumulative forward trajectory sum from AR(5)
            fwd_port_sum = float(np.sum(predicted_deltas[:, port_idx]))
            fwd_flow_sum = float(np.sum(predicted_deltas[:, flow_idx]))
            fwd_byte_sum = float(np.sum(predicted_deltas[:, byte_idx]))

            # Channel A: Reconnaissance Port Diversity Acceleration
            # Conditions:
            # - Positive acceleration exceeding threshold
            # - Positive current velocity
            # - Forward AR(5) forecast confirms non-dissipating expansion (fwd_port_sum > 0)
            # - Current state at or above inflection floor
            # - Second-order projection crosses threshold
            if (
                port_accel >= self.accel_port_thresh
                and port_vel > 0.0
                and fwd_port_sum > 0.0
                and cur_port >= (self.inflection_ratio * self.recon_port_thresh)
            ):
                for h in range(predicted_deltas.shape[0]):
                    cum_lin = cur_port + float(np.sum(predicted_deltas[: h + 1, port_idx]))
                    cum_accel = cum_lin + (self.accel_beta * (h + 1) * port_accel)
                    if cum_accel >= self.recon_port_thresh:
                        return DetectionResult(
                            is_alert=True,
                            event_type="Reconnaissance",
                            confidence=0.85 if trust_level == TrustLevel.HIGH else 0.70,
                            trigger_reason=(
                                f"Acceleration-augmented inflection predicts Reconnaissance at h={h+1} "
                                f"(Δ²={port_accel:.1f} >= {self.accel_port_thresh}, Δ={port_vel:.1f}, "
                                f"AR(5)_fwd=+{fwd_port_sum:.1f}, Trust={trust_level.value})"
                            ),
                            feature_values=vals,
                        )

            # Channel B: Denial of Service Flow Count Acceleration
            if (
                flow_accel >= self.accel_flow_thresh
                and flow_vel > 0.0
                and fwd_flow_sum > 0.0
                and cur_flow >= (self.inflection_ratio * self.dos_flow_thresh)
            ):
                for h in range(predicted_deltas.shape[0]):
                    cum_lin = cur_flow + float(np.sum(predicted_deltas[: h + 1, flow_idx]))
                    cum_accel = cum_lin + (self.accel_beta * (h + 1) * flow_accel)
                    if cum_accel >= self.dos_flow_thresh:
                        return DetectionResult(
                            is_alert=True,
                            event_type="Impact / Denial of Service",
                            confidence=0.80 if trust_level == TrustLevel.HIGH else 0.65,
                            trigger_reason=(
                                f"Acceleration-augmented inflection predicts DoS at h={h+1} "
                                f"(Δ²={flow_accel:.1f} >= {self.accel_flow_thresh}, Δ={flow_vel:.1f}, "
                                f"AR(5)_fwd=+{fwd_flow_sum:.1f}, Trust={trust_level.value})"
                            ),
                            feature_values=vals,
                        )

            # Channel C: Exfiltration Byte Rate Acceleration
            if (
                byte_accel >= self.accel_byte_thresh
                and byte_vel > 0.0
                and fwd_byte_sum > 0.0
                and cur_byte >= (self.inflection_ratio * self.exfil_byte_thresh)
            ):
                for h in range(predicted_deltas.shape[0]):
                    cum_lin = cur_byte + float(np.sum(predicted_deltas[: h + 1, byte_idx]))
                    cum_accel = cum_lin + (self.accel_beta * (h + 1) * byte_accel)
                    if cum_accel >= self.exfil_byte_thresh:
                        return DetectionResult(
                            is_alert=True,
                            event_type="Collection / Exfiltration",
                            confidence=0.75 if trust_level == TrustLevel.HIGH else 0.60,
                            trigger_reason=(
                                f"Acceleration-augmented inflection predicts Exfiltration at h={h+1} "
                                f"(Δ²={byte_accel:,.0f} >= {self.accel_byte_thresh:,.0f}, Δ={byte_vel:,.0f}, "
                                f"AR(5)_fwd=+{fwd_byte_sum:,.0f}, Trust={trust_level.value})"
                            ),
                            feature_values=vals,
                        )

        # 4. Seamless fallback to standard PredictiveTrajectoryDetector decision rule
        return super().evaluate_state_and_forecast(
            current_state=current_state,
            predicted_deltas=predicted_deltas,
            trust_level=trust_level,
        )
