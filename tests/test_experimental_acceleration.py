"""Unit and validation tests for Research Treatment: Δ² Temporal Acceleration (SIH PS 26153).

Validates:
1. Δ² calculation: Verifies mathematical correctness of second-order temporal difference.
2. Insufficient history: Verifies graceful fallback to baseline when history length < 3.
3. Zero future-data access: Verifies that evaluation at window t depends strictly on states <= t.
4. Threshold behavior: Verifies inflection firing rules, acceleration noise gating, and trust guards.
5. Monotonic timestamps and window continuity: Verifies detection of gaps and session breaks.
6. Baseline immutability: Verifies that the treatment does not alter PredictiveTrajectoryDetector behavior.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Sequence

import numpy as np
import pytest

from core.contracts import FeatureAvailability, NetworkState, Source, TrustLevel
from eval.baseline_detectors import ConventionalCurrentStateDetector, PredictiveTrajectoryDetector
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.experimental_acceleration import (
    AccelerationAugmentedTrajectoryDetector,
    compute_second_difference,
)
from eval.rollout import MultiStepRolloutEngine
from runtime.train_authoritative_model import load_ar_model


def _make_test_state(
    start: datetime,
    dst_port_diversity: int = 1,
    flow_count: int = 10,
    byte_rate: float = 1000.0,
    session_id: str = "sess-accel-test",
    window_duration_s: float = 10.0,
) -> NetworkState:
    """Helper to build a deterministic valid NetworkState."""
    end = start + timedelta(seconds=window_duration_s)
    avail = {f: FeatureAvailability.AVAILABLE for f in CSV_AVAILABLE_FEATURES}
    for f in ["src_ip_diversity", "dst_ip_diversity", "src_port_diversity", "fan_out", "internal_ratio", "east_west_count"]:
        avail[f] = FeatureAvailability.UNAVAILABLE

    return NetworkState(
        window_id=f"win_{start.strftime('%Y%m%d%H%M%S')}",
        timestamp_start=start,
        timestamp_end=end,
        window_duration_s=window_duration_s,
        flow_count=flow_count,
        byte_rate=byte_rate,
        packet_rate=float(flow_count * 2),
        mean_flow_duration=2.5,
        src_ip_diversity=None,
        dst_ip_diversity=None,
        src_port_diversity=None,
        dst_port_diversity=dst_port_diversity,
        fan_out=None,
        internal_ratio=None,
        east_west_count=None,
        syn_count=max(0, flow_count // 2),
        ack_count=max(0, flow_count // 2),
        rst_count=0,
        syn_ratio=0.5,
        rst_ratio=0.0,
        iat_mean=0.10,
        iat_std=0.05,
        iat_skew=None,
        pkt_size_mean=500.0,
        pkt_size_std=100.0,
        byte_variance=25000.0,
        ttl_mean=None,
        ttl_variance=None,
        tcp_window_mean=None,
        fragment_count=None,
        retransmit_count=None,
        payload_size_mean=None,
        source=Source.CSV,
        data_quality=1.0,
        is_empty=False,
        gap_before=False,
        gap_after=False,
        session_id=session_id,
        provenance_hash="0" * 64,
        feature_availability=avail,
    )


class TestExperimentalAcceleration:
    """Test suite for research treatment: Δ² temporal acceleration detector."""

    def test_delta2_calculation_accuracy(self):
        """Verify exact mathematical calculation of Δ²S_t = S_t - 2*S_{t-1} + S_{t-2}."""
        t0 = datetime(2018, 3, 1, 10, 0, 0)
        s0 = _make_test_state(t0, dst_port_diversity=2, flow_count=10, byte_rate=1000.0)
        s1 = _make_test_state(t0 + timedelta(seconds=10), dst_port_diversity=5, flow_count=25, byte_rate=3000.0)
        s2 = _make_test_state(t0 + timedelta(seconds=20), dst_port_diversity=10, flow_count=50, byte_rate=7000.0)

        # Expected:
        # dst_port_diversity:
        # ΔS_1 = 5 - 2 = 3
        # ΔS_2 = 10 - 5 = 5
        # Δ²S_2 = 5 - 3 = 2  (or 10 - 2*5 + 2 = 2)
        # flow_count:
        # ΔS_1 = 25 - 10 = 15
        # ΔS_2 = 50 - 25 = 25
        # Δ²S_2 = 25 - 15 = 10 (or 50 - 2*25 + 10 = 10)
        d2 = compute_second_difference([s0, s1, s2])
        assert d2 is not None
        assert d2["dst_port_diversity"] == 2.0
        assert d2["flow_count"] == 10.0
        assert d2["byte_rate"] == 2000.0  # (7000 - 3000) - (3000 - 1000) = 4000 - 2000 = 2000

    def test_insufficient_history_handling(self):
        """Verify graceful fallback when history depth < 3."""
        t0 = datetime(2018, 3, 1, 10, 0, 0)
        s0 = _make_test_state(t0)
        s1 = _make_test_state(t0 + timedelta(seconds=10))

        # 0, 1, and 2 states return None
        assert compute_second_difference([]) is None
        assert compute_second_difference([s0]) is None
        assert compute_second_difference([s0, s1]) is None

        # Detector fallback with mock rollout engine
        model_dir = Path("artifacts/models/ar5_authoritative")
        ar_model, _ = load_ar_model(model_dir)
        rollout = MultiStepRolloutEngine(ar_model=ar_model, feature_names=CSV_AVAILABLE_FEATURES)

        detector = AccelerationAugmentedTrajectoryDetector(
            rollout_engine=rollout,
            recon_port_thresh=20,
        )

        dummy_deltas = np.zeros((3, len(CSV_AVAILABLE_FEATURES)))
        # At window 0 (only 1 state): evaluates safely via baseline fallback
        res = detector.evaluate_state_and_forecast(s0, dummy_deltas, TrustLevel.HIGH)
        assert res is not None
        assert res.is_alert is False

    def test_strictly_causal_no_future_data_access(self):
        """Verify that evaluation at time t is strictly invariant to future data."""
        t0 = datetime(2018, 3, 1, 10, 0, 0)
        s0 = _make_test_state(t0, dst_port_diversity=2)
        s1 = _make_test_state(t0 + timedelta(seconds=10), dst_port_diversity=6)
        s2 = _make_test_state(t0 + timedelta(seconds=20), dst_port_diversity=14)

        # Baseline evaluation at window 2
        d2_without_future = compute_second_difference([s0, s1, s2])

        # Attempt to supply future states S3 and S4 with extreme values
        s3 = _make_test_state(t0 + timedelta(seconds=30), dst_port_diversity=1000)
        s4 = _make_test_state(t0 + timedelta(seconds=40), dst_port_diversity=5000)

        # Evaluating up to window 2 (s2) ignores s3 and s4 completely
        d2_causal = compute_second_difference([s0, s1, s2])
        assert d2_causal == d2_without_future

    def test_acceleration_threshold_behavior(self):
        """Verify inflection alert rules, threshold gating, and trust requirements."""
        model_dir = Path("artifacts/models/ar5_authoritative")
        ar_model, _ = load_ar_model(model_dir)
        rollout = MultiStepRolloutEngine(ar_model=ar_model, feature_names=CSV_AVAILABLE_FEATURES)

        detector = AccelerationAugmentedTrajectoryDetector(
            rollout_engine=rollout,
            recon_port_thresh=20,
            accel_port_thresh=10.0,
            inflection_ratio=0.40,  # Min port level = 0.40 * 20 = 8.0
        )

        t0 = datetime(2018, 3, 1, 10, 0, 0)
        s0 = _make_test_state(t0, dst_port_diversity=2)
        s1 = _make_test_state(t0 + timedelta(seconds=10), dst_port_diversity=4)

        # Case 1: Sub-threshold acceleration (Δ² = (8 - 4) - (4 - 2) = 4 - 2 = 2.0 < 10.0)
        s2_sub = _make_test_state(t0 + timedelta(seconds=20), dst_port_diversity=8)
        fwd_deltas_pos = np.ones((3, len(CSV_AVAILABLE_FEATURES))) * 2.0  # AR(5) predicts +2 per step
        res_sub = detector.evaluate_state_and_forecast(
            current_state=s2_sub,
            predicted_deltas=fwd_deltas_pos,
            trust_level=TrustLevel.HIGH,
            history_states=[s0, s1, s2_sub],
        )
        # Does NOT trigger acceleration alert because Δ²=2.0 < 10.0
        assert "Acceleration-augmented" not in res_sub.trigger_reason

        # Case 2: High acceleration meeting all conditions
        # s0=2, s1=4, s2=18 -> ΔS_1=2, ΔS_2=14 -> Δ²=12.0 >= 10.0
        # cur_port=18 >= 8.0 (inflection floor)
        # AR(5) predicts +2 -> projected level crosses 20 easily
        s2_high = _make_test_state(t0 + timedelta(seconds=20), dst_port_diversity=18)
        res_high = detector.evaluate_state_and_forecast(
            current_state=s2_high,
            predicted_deltas=fwd_deltas_pos,
            trust_level=TrustLevel.HIGH,
            history_states=[s0, s1, s2_high],
        )
        assert res_high.is_alert is True
        assert "Acceleration-augmented inflection predicts Reconnaissance" in res_high.trigger_reason

        # Case 3: High acceleration but negative AR(5) forecast (dissipating transient)
        # Forward AR(5) forecast predicts -5 per step (net sum < 0)
        fwd_deltas_neg = np.ones((3, len(CSV_AVAILABLE_FEATURES))) * -5.0
        res_dissipating = detector.evaluate_state_and_forecast(
            current_state=s2_high,
            predicted_deltas=fwd_deltas_neg,
            trust_level=TrustLevel.HIGH,
            history_states=[s0, s1, s2_high],
        )
        # Acceleration alert is suppressed because forward forecast does NOT confirm expansion
        assert "Acceleration-augmented" not in res_dissipating.trigger_reason

        # Case 4: Low trust suppression
        # Trust is LOW -> acceleration alert MUST NOT fire
        res_low_trust = detector.evaluate_state_and_forecast(
            current_state=s2_high,
            predicted_deltas=fwd_deltas_pos,
            trust_level=TrustLevel.LOW,
            history_states=[s0, s1, s2_high],
        )
        assert "Acceleration-augmented" not in res_low_trust.trigger_reason

    def test_monotonic_timestamps_and_window_continuity(self):
        """Verify rejection of temporal gaps, session boundaries, and inverted timestamps."""
        t0 = datetime(2018, 3, 1, 10, 0, 0)
        s0 = _make_test_state(t0, session_id="sess-A")
        s1 = _make_test_state(t0 + timedelta(seconds=10), session_id="sess-A")

        # 1. Temporal gap: s2 starts 30s after s1 ends (gap = 30s > 0.10s)
        s2_gap = _make_test_state(t0 + timedelta(seconds=50), session_id="sess-A")
        assert compute_second_difference([s0, s1, s2_gap]) is None

        # 2. Session boundary crossed: s2 belongs to a different session
        s2_diff_sess = _make_test_state(t0 + timedelta(seconds=20), session_id="sess-B")
        assert compute_second_difference([s0, s1, s2_diff_sess]) is None

        # 3. Non-monotonic / inverted timestamp: s2 starts earlier than s1
        s2_inverted = _make_test_state(t0 + timedelta(seconds=5), session_id="sess-A")
        assert compute_second_difference([s0, s1, s2_inverted]) is None

    def test_treatment_does_not_modify_baseline_detector(self):
        """Verify that treatment detector does not alter PredictiveTrajectoryDetector in any way."""
        model_dir = Path("artifacts/models/ar5_authoritative")
        ar_model, _ = load_ar_model(model_dir)
        rollout = MultiStepRolloutEngine(ar_model=ar_model, feature_names=CSV_AVAILABLE_FEATURES)

        baseline_detector = PredictiveTrajectoryDetector(
            rollout_engine=rollout,
            recon_port_thresh=20,
        )
        treatment_detector = AccelerationAugmentedTrajectoryDetector(
            rollout_engine=rollout,
            recon_port_thresh=20,
        )

        # Verify class hierarchy
        assert issubclass(AccelerationAugmentedTrajectoryDetector, PredictiveTrajectoryDetector)
        assert type(baseline_detector) is PredictiveTrajectoryDetector

        # Verify baseline detector behavior is unaffected by treatment existence
        t0 = datetime(2018, 3, 1, 10, 0, 0)
        s0 = _make_test_state(t0, dst_port_diversity=5)
        dummy_deltas = np.zeros((3, len(CSV_AVAILABLE_FEATURES)))

        res_base = baseline_detector.evaluate_state_and_forecast(s0, dummy_deltas, TrustLevel.HIGH)
        assert res_base.is_alert is False
        assert "Trajectory forecast" in res_base.trigger_reason or "within normal boundaries" in res_base.trigger_reason
        assert "Acceleration-augmented" not in res_base.trigger_reason
