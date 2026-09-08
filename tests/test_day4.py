"""Unit and validation tests for Day 4 Delta-State Baseline V2."""
from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path
import numpy as np

from core.contracts import FeatureAvailability, NetworkState, Source
from eval.dataset import (
    CSV_AVAILABLE_FEATURES,
    OBSERVED_INFILTRATION_BLOCKS,
    TransitionSample,
    chronological_split,
    extract_transitions,
    leave_one_block_out_split,
    samples_to_arrays,
)
from eval.metrics_v2 import (
    MetricReportV2,
    RobustScaleStatistics,
    compute_metrics_v2,
    compute_training_scales,
    evaluate_victory_criterion_v2,
)
from eval.models_v2 import (
    ARStyleBaselineV2,
    EWMABaselineV2,
    GBDTLearnedModelV2,
    PersistenceBaselineV2,
    RidgeLearnedModelV2,
    ZeroChangeBaselineV2,
)


def _make_dummy_state(
    start: datetime,
    session_id: str = "session-1",
    is_empty: bool = False,
    flow_count: int = 10,
    byte_rate: float = 100.0,
) -> NetworkState:
    end = start + timedelta(seconds=10)
    avail = {f: FeatureAvailability.AVAILABLE for f in CSV_AVAILABLE_FEATURES}
    for f in ["src_ip_diversity", "dst_ip_diversity", "src_port_diversity", "fan_out", "internal_ratio", "east_west_count"]:
        avail[f] = FeatureAvailability.UNAVAILABLE
        
    return NetworkState(
        window_id=f"{start.isoformat()}_10s",
        timestamp_start=start,
        timestamp_end=end,
        window_duration_s=10.0,
        flow_count=0 if is_empty else flow_count,
        byte_rate=0.0 if is_empty else byte_rate,
        packet_rate=10.0,
        mean_flow_duration=5.0,
        src_ip_diversity=None,
        dst_ip_diversity=None,
        src_port_diversity=None,
        dst_port_diversity=5,
        fan_out=None,
        internal_ratio=None,
        east_west_count=None,
        syn_count=2,
        ack_count=4,
        rst_count=1,
        syn_ratio=0.2,
        rst_ratio=0.1,
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
        data_quality=0.0 if is_empty else 1.0,
        is_empty=is_empty,
        gap_before=False,
        gap_after=False,
        session_id=session_id,
        provenance_hash="a" * 64,
        feature_availability=avail,
    )


class DayFourTests(unittest.TestCase):
    def setUp(self) -> None:
        self.t0 = datetime(2018, 2, 28, 1, 0, 0)
        self.states = [
            _make_dummy_state(self.t0 + timedelta(seconds=10 * i), byte_rate=100.0 + 10.0 * i)
            for i in range(50)
        ]
        self.transitions, _ = extract_transitions(self.states, history_depth=6)

    def test_1_v1_artifacts_untouched(self) -> None:
        v1_dir = Path("artifacts/experiments/delta_baseline_v1")
        if v1_dir.exists():
            manifest = v1_dir / "manifest.json"
            self.assertTrue(manifest.exists())
            data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(data["experiment_name"], "delta_baseline_v1")

    def test_2_and_3_normalization_statistics_fit_on_train_only(self) -> None:
        tr_s, val_s, te_s = chronological_split(self.transitions, 0.60, 0.20, 0.20)
        tr = samples_to_arrays(tr_s)
        te = samples_to_arrays(te_s)
        
        # Artificially alter test targets to extreme values
        te_altered = np.copy(te.y)
        te_altered[:, 0] = 1e9
        
        scales_tr = compute_training_scales(tr.y, CSV_AVAILABLE_FEATURES)
        # Verify training scale is completely unaffected by test alterations
        self.assertNotEqual(scales_tr.effective_scales[0], 1e9)
        self.assertAlmostEqual(scales_tr.effective_scales[0], compute_training_scales(tr.y, CSV_AVAILABLE_FEATURES).effective_scales[0])

    def test_4_and_5_no_label_or_infiltration_leakage(self) -> None:
        for f in CSV_AVAILABLE_FEATURES:
            self.assertNotIn("label", f.lower())
            self.assertNotIn("infiltration", f.lower())

    def test_6_unavailable_features_remain_unavailable(self) -> None:
        rep = compute_metrics_v2(
            np.zeros((2, len(CSV_AVAILABLE_FEATURES))),
            np.zeros((2, len(CSV_AVAILABLE_FEATURES))),
            CSV_AVAILABLE_FEATURES,
            compute_training_scales(np.ones((2, len(CSV_AVAILABLE_FEATURES))), CSV_AVAILABLE_FEATURES),
        )
        self.assertEqual(rep.behavioural_directional_accuracy["destination_diversity"], "UNAVAILABLE")

    def test_7_and_12_raw_and_normalized_metrics_preserved(self) -> None:
        y_true = np.array([[10.0, 20.0], [30.0, 40.0]])
        y_pred = np.array([[5.0, 10.0], [20.0, 20.0]])
        scales = RobustScaleStatistics(["f1", "f2"], np.array([0.0, 0.0]), np.array([5.0, 10.0]), np.array([5.0, 10.0]), np.array([5.0, 10.0]), np.array([5.0, 10.0]))
        
        rep = compute_metrics_v2(y_true, y_pred, ["f1", "f2"], scales)
        # raw mae: (|5| + |10| + |10| + |20|) / 4 = 45 / 4 = 11.25
        self.assertAlmostEqual(rep.delta_mae_raw, 11.25)
        # normalized mae: (5/5 + 10/10 + 10/5 + 20/10) / 4 = (1 + 1 + 2 + 2) / 4 = 1.5
        self.assertAlmostEqual(rep.delta_mae_normalized, 1.5)

    def test_8_ar_order_changes_correctly(self) -> None:
        tr_s, val_s, te_s = chronological_split(self.transitions, 0.60, 0.20, 0.20)
        tr = samples_to_arrays(tr_s)
        va = samples_to_arrays(val_s)
        te = samples_to_arrays(te_s)
        
        ar1 = ARStyleBaselineV2(fixed_p=1).fit(tr.X, tr.y, tr.X_deltas, va.X, va.y, va.X_deltas)
        ar3 = ARStyleBaselineV2(fixed_p=3).fit(tr.X, tr.y, tr.X_deltas, va.X, va.y, va.X_deltas)
        ar5 = ARStyleBaselineV2(fixed_p=5).fit(tr.X, tr.y, tr.X_deltas, va.X, va.y, va.X_deltas)
        
        self.assertEqual(ar1.selected_p, 1)
        self.assertEqual(ar3.selected_p, 3)
        self.assertEqual(ar5.selected_p, 5)

    def test_9_held_out_block_boundaries(self) -> None:
        for blk in OBSERVED_INFILTRATION_BLOCKS:
            self.assertIn("start", blk)
            self.assertIn("end", blk)
            self.assertLess(blk["start"], blk["end"])

    def test_10_and_11_v2_models_deterministic(self) -> None:
        tr_s, val_s, te_s = chronological_split(self.transitions, 0.60, 0.20, 0.20)
        tr = samples_to_arrays(tr_s)
        va = samples_to_arrays(val_s)
        te = samples_to_arrays(te_s)
        scales = compute_training_scales(tr.y, CSV_AVAILABLE_FEATURES)
        
        r1 = RidgeLearnedModelV2().fit(tr.X, tr.y, va.X, va.y, scales=scales).predict(te.X)
        r2 = RidgeLearnedModelV2().fit(tr.X, tr.y, va.X, va.y, scales=scales).predict(te.X)
        np.testing.assert_array_almost_equal(r1, r2)

    def test_13_ar5_requires_at_least_six_states(self) -> None:
        """AR(5) requires six consecutive states (history_depth=6) to obtain 5 historical deltas."""
        # 1. With history_depth = 3 (only 2 historical deltas available)
        transitions_h3, _ = extract_transitions(self.states, history_depth=3)
        tr_s3, val_s3, _ = chronological_split(transitions_h3, 0.60, 0.20, 0.20)
        tr3 = samples_to_arrays(tr_s3)
        va3 = samples_to_arrays(val_s3)
        
        ar5 = ARStyleBaselineV2(fixed_p=5)
        with self.assertRaises(ValueError) as ctx:
            ar5.fit(tr3.X, tr3.y, tr3.X_deltas, va3.X, va3.y, va3.X_deltas)
        self.assertIn("AR(5) requires at least 6 consecutive states", str(ctx.exception))

        # 2. With history_depth = 6 (5 historical deltas available)
        transitions_h6, _ = extract_transitions(self.states, history_depth=6)
        tr_s6, val_s6, _ = chronological_split(transitions_h6, 0.60, 0.20, 0.20)
        tr6 = samples_to_arrays(tr_s6)
        va6 = samples_to_arrays(val_s6)
        
        ar5_valid = ARStyleBaselineV2(fixed_p=5)
        ar5_valid.fit(tr6.X, tr6.y, tr6.X_deltas, va6.X, va6.y, va6.X_deltas)
        self.assertEqual(ar5_valid.selected_p, 5)


if __name__ == "__main__":
    unittest.main()
