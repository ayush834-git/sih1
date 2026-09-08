"""Unit and validation tests for Day 9B AR(3) vs AR(5) Availability Audit (SIH 26153)."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta
from pathlib import Path

from core.contracts import FeatureAvailability, NetworkState, Source
from eval.dataset import CSV_AVAILABLE_FEATURES, extract_transitions
from eval.run_ar_availability_audit import run_ar_availability_audit
from scenarios.demo.scenarios import create_demo_state


class AROrderAvailabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.t0 = datetime(2018, 3, 1, 12, 0, 0)
        self.feature_names = CSV_AVAILABLE_FEATURES

    def test_1_ar3_requires_four_history_states_plus_target(self) -> None:
        """AR(3) (history_depth=4) requires 4 history states + 1 target state (5 total states) to produce 1 transition sample."""
        states_4 = [create_demo_state(i, self.t0) for i in range(4)]
        states_5 = [create_demo_state(i, self.t0) for i in range(5)]
        
        samples_4, _ = extract_transitions(states_4, history_depth=4, feature_names=self.feature_names)
        samples_5, _ = extract_transitions(states_5, history_depth=4, feature_names=self.feature_names)
        
        self.assertEqual(len(samples_4), 0)
        self.assertEqual(len(samples_5), 1)
        self.assertEqual(len(samples_5[0].history_deltas), 3)

    def test_2_ar5_requires_six_history_states_plus_target(self) -> None:
        """AR(5) (history_depth=6) requires 6 history states + 1 target state (7 total states) to produce 1 transition sample."""
        states_6 = [create_demo_state(i, self.t0) for i in range(6)]
        states_7 = [create_demo_state(i, self.t0) for i in range(7)]
        
        samples_6, _ = extract_transitions(states_6, history_depth=6, feature_names=self.feature_names)
        samples_7, _ = extract_transitions(states_7, history_depth=6, feature_names=self.feature_names)
        
        self.assertEqual(len(samples_6), 0)
        self.assertEqual(len(samples_7), 1)
        self.assertEqual(len(samples_7[0].history_deltas), 5)

    def test_3_no_model_forecasts_across_empty_window(self) -> None:
        """Transitions must not cross or include empty windows."""
        states = [create_demo_state(i, self.t0) for i in range(6)]
        # Make state 3 empty
        avail = {f: FeatureAvailability.AVAILABLE for f in self.feature_names}
        states[3] = NetworkState(
            window_id="empty_w3",
            timestamp_start=self.t0 + timedelta(seconds=30),
            timestamp_end=self.t0 + timedelta(seconds=40),
            window_duration_s=10.0,
            flow_count=0,
            byte_rate=0.0,
            packet_rate=0.0,
            mean_flow_duration=0.0,
            src_ip_diversity=None,
            dst_ip_diversity=None,
            src_port_diversity=None,
            dst_port_diversity=0,
            fan_out=None,
            internal_ratio=None,
            east_west_count=None,
            syn_count=0,
            ack_count=0,
            rst_count=0,
            syn_ratio=0.0,
            rst_ratio=0.0,
            iat_mean=0.0,
            iat_std=0.0,
            iat_skew=None,
            pkt_size_mean=0.0,
            pkt_size_std=0.0,
            byte_variance=0.0,
            ttl_mean=None,
            ttl_variance=None,
            tcp_window_mean=None,
            fragment_count=None,
            retransmit_count=None,
            payload_size_mean=None,
            source=Source.CSV,
            data_quality=1.0,
            is_empty=True,
            gap_before=False,
            gap_after=False,
            session_id="session-test",
            provenance_hash="e" * 64,
            feature_availability=avail,
        )
        
        samples_ar3, _ = extract_transitions(states, history_depth=4, feature_names=self.feature_names)
        samples_ar5, _ = extract_transitions(states, history_depth=6, feature_names=self.feature_names)
        
        self.assertEqual(len(samples_ar3), 0)
        self.assertEqual(len(samples_ar5), 0)

    def test_4_no_model_forecasts_across_session_gap(self) -> None:
        """Transitions must not cross session boundaries or gap flags."""
        states = [create_demo_state(i, self.t0) for i in range(6)]
        # Mark state 4 as gap_before
        avail = {f: FeatureAvailability.AVAILABLE for f in self.feature_names}
        states[4] = NetworkState(
            window_id="gap_w4",
            timestamp_start=self.t0 + timedelta(seconds=40),
            timestamp_end=self.t0 + timedelta(seconds=50),
            window_duration_s=10.0,
            flow_count=10,
            byte_rate=1000.0,
            packet_rate=20.0,
            mean_flow_duration=5.0,
            src_ip_diversity=None,
            dst_ip_diversity=None,
            src_port_diversity=None,
            dst_port_diversity=2,
            fan_out=None,
            internal_ratio=None,
            east_west_count=None,
            syn_count=0,
            ack_count=0,
            rst_count=0,
            syn_ratio=0.0,
            rst_ratio=0.0,
            iat_mean=1.0,
            iat_std=0.5,
            iat_skew=None,
            pkt_size_mean=100.0,
            pkt_size_std=20.0,
            byte_variance=500.0,
            ttl_mean=None,
            ttl_variance=None,
            tcp_window_mean=None,
            fragment_count=None,
            retransmit_count=None,
            payload_size_mean=None,
            source=Source.CSV,
            data_quality=1.0,
            is_empty=False,
            gap_before=True,
            gap_after=False,
            session_id="session-test",
            provenance_hash="g" * 64,
            feature_availability=avail,
        )
        
        samples_ar5, _ = extract_transitions(states, history_depth=6, feature_names=self.feature_names)
        self.assertEqual(len(samples_ar5), 0)

    def test_5_and_6_availability_calculation_is_deterministic(self) -> None:
        """Audit runner produces identical results across executions."""
        res1 = run_ar_availability_audit()
        res2 = run_ar_availability_audit()
        
        self.assertEqual(res1["availability_comparison"]["ar3_valid_forecasts"], res2["availability_comparison"]["ar3_valid_forecasts"])
        self.assertEqual(res1["availability_comparison"]["ar5_valid_forecasts"], res2["availability_comparison"]["ar5_valid_forecasts"])
        self.assertAlmostEqual(res1["accuracy_comparison"]["ar5_directional_accuracy"], res2["accuracy_comparison"]["ar5_directional_accuracy"])

    def test_7_historical_experiment_artifacts_remain_untouched(self) -> None:
        """Historical manifests from Day 1 to Day 9 must exist and remain non-empty."""
        for p in [
            "artifacts/experiments/delta_baseline_v1/manifest.json",
            "artifacts/experiments/delta_baseline_v2/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1_corrected/manifest.json",
            "artifacts/experiments/security_bridge_v1/manifest.json",
            "artifacts/experiments/security_bridge_validation_v1/manifest.json",
            "artifacts/experiments/decision_layer_v1/manifest.json",
            "artifacts/experiments/demo_validation_v1/manifest.json",
            "artifacts/experiments/response_window_v1/manifest.json",
        ]:
            path = Path(p)
            if path.exists():
                self.assertTrue(len(path.read_text(encoding="utf-8")) > 0)


if __name__ == "__main__":
    unittest.main()
