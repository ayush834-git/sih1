"""Unit and validation tests for Day-3 Delta-State Baseline Experiment."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta
import numpy as np
from sklearn.preprocessing import RobustScaler

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
from eval.metrics import (
    BEHAVIOURAL_DIMENSIONS,
    MetricReport,
    compute_metrics,
    evaluate_victory_criterion,
)
from eval.models import (
    ARStyleBaseline,
    EWMABaseline,
    GBDTLearnedModel,
    PersistenceBaseline,
    RidgeLearnedModel,
    ZeroChangeBaseline,
)


def _make_dummy_state(
    start: datetime,
    session_id: str = "session-1",
    is_empty: bool = False,
    gap_before: bool = False,
    gap_after: bool = False,
    flow_count: int = 10,
    byte_rate: float = 100.0,
    packet_rate: float = 10.0,
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
        packet_rate=0.0 if is_empty else packet_rate,
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
        gap_before=gap_before,
        gap_after=gap_after,
        session_id=session_id,
        provenance_hash="a" * 64,
        feature_availability=avail,
    )


class DayThreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.t0 = datetime(2018, 2, 28, 1, 0, 0)
        self.states = [
            _make_dummy_state(self.t0 + timedelta(seconds=10 * i), byte_rate=100.0 + 10.0 * i)
            for i in range(10)
        ]

    def test_transition_extraction_contiguous(self) -> None:
        transitions, dropped = extract_transitions(self.states, history_depth=3)
        # 10 states with window_len=4 -> 7 samples
        self.assertEqual(len(transitions), 7)
        self.assertEqual(sum(dropped.values()), 0)
        first = transitions[0]
        self.assertEqual(len(first.history_states), 3)
        self.assertAlmostEqual(first.delta["byte_rate"], 10.0)

    def test_transition_rejection_on_empty_and_session_gap(self) -> None:
        dirty_states = list(self.states)
        # Make state 4 empty
        dirty_states[4] = _make_dummy_state(self.t0 + timedelta(seconds=40), is_empty=True)
        # Make state 8 a different session
        dirty_states[8] = _make_dummy_state(self.t0 + timedelta(seconds=80), session_id="session-2")
        
        transitions, dropped = extract_transitions(dirty_states, history_depth=3)
        self.assertGreater(dropped["empty_state_in_window"], 0)
        self.assertGreater(dropped["session_boundary_crossed"], 0)
        self.assertLess(len(transitions), 7)

    def test_no_label_or_infiltration_leakage_in_features(self) -> None:
        self.assertNotIn("Label", CSV_AVAILABLE_FEATURES)
        self.assertNotIn("label", CSV_AVAILABLE_FEATURES)
        self.assertNotIn("infiltration_fraction", CSV_AVAILABLE_FEATURES)
        
        transitions, _ = extract_transitions(self.states, history_depth=3)
        arr = samples_to_arrays(transitions)
        self.assertEqual(arr.y.shape[1], len(CSV_AVAILABLE_FEATURES))
        for f in arr.feature_names:
            self.assertNotIn("label", f.lower())
            self.assertNotIn("infiltration", f.lower())

    def test_chronological_split(self) -> None:
        states = [_make_dummy_state(self.t0 + timedelta(seconds=10 * i)) for i in range(30)]
        transitions, _ = extract_transitions(states, history_depth=3)
        tr, val, te = chronological_split(transitions, 0.60, 0.20, 0.20)
        
        self.assertEqual(len(tr) + len(val) + len(te), len(transitions))
        self.assertLess(tr[-1].target_start, val[0].target_start)
        self.assertLess(val[-1].target_start, te[0].target_start)

    def test_leave_one_block_out_split(self) -> None:
        blk = OBSERVED_INFILTRATION_BLOCKS[0]
        # Create states spanning before, during, and after block 1
        b_start = blk["start"]
        states = [_make_dummy_state(b_start - timedelta(minutes=10) + timedelta(seconds=10 * i)) for i in range(100)]
        transitions, _ = extract_transitions(states, history_depth=3)
        tr, val, te = leave_one_block_out_split(transitions, blk)
        
        for s in te:
            self.assertTrue(blk["start"] <= s.target_start <= blk["end"])
        for s in tr + val:
            self.assertFalse(blk["start"] <= s.target_start <= blk["end"])

    def test_scaler_fit_isolation(self) -> None:
        states = [_make_dummy_state(self.t0 + timedelta(seconds=10 * i), byte_rate=float(i * 100)) for i in range(50)]
        transitions, _ = extract_transitions(states, history_depth=3)
        tr, val, te = chronological_split(transitions, 0.60, 0.20, 0.20)
        tr_arr = samples_to_arrays(tr)
        te_arr = samples_to_arrays(te)
        
        # byte_rate is feature index 1
        scaler_tr = RidgeLearnedModel().fit(tr_arr.X, tr_arr.y, tr_arr.X, tr_arr.y).scaler
        scaler_te = RobustScaler().fit(te_arr.X)
        self.assertNotEqual(scaler_tr.center_[1], scaler_te.center_[1])

    def test_baseline_models_execution(self) -> None:
        states = [
            _make_dummy_state(self.t0 + timedelta(seconds=10 * i), byte_rate=100.0 + np.sin(i) * 50.0)
            for i in range(40)
        ]
        transitions, _ = extract_transitions(states, history_depth=3)
        tr_s, val_s, te_s = chronological_split(transitions, 0.60, 0.20, 0.20)
        tr = samples_to_arrays(tr_s)
        va = samples_to_arrays(val_s)
        te = samples_to_arrays(te_s)
        
        # B1. ZeroChange
        b1 = ZeroChangeBaseline().fit(tr.X, tr.y)
        p1 = b1.predict(te.X, te.X_deltas, len(CSV_AVAILABLE_FEATURES))
        self.assertTrue(np.all(p1 == 0))
        
        # B2. Persistence
        b2 = PersistenceBaseline().fit(tr.X, tr.y)
        p2 = b2.predict(te.X, te.X_deltas, len(CSV_AVAILABLE_FEATURES))
        self.assertEqual(p2.shape, te.y.shape)
        
        # B3. EWMA
        b3 = EWMABaseline(candidate_alphas=[0.1, 0.3, 0.5])
        b3.fit(tr.X, tr.y, tr.X_deltas, va.X, va.y, va.X_deltas)
        p3 = b3.predict(te.X, te.X_deltas, len(CSV_AVAILABLE_FEATURES))
        self.assertEqual(p3.shape, te.y.shape)
        self.assertIn(b3.selected_alpha, [0.1, 0.3, 0.5])
        
        # B4. AR-style
        b4 = ARStyleBaseline(candidate_p=[1, 2])
        b4.fit(tr.X, tr.y, tr.X_deltas, va.X, va.y, va.X_deltas)
        p4 = b4.predict(te.X, te.X_deltas, len(CSV_AVAILABLE_FEATURES))
        self.assertEqual(p4.shape, te.y.shape)
        
        # B5. Ridge
        b5 = RidgeLearnedModel(candidate_alphas=[0.1, 1.0, 10.0])
        b5.fit(tr.X, tr.y, va.X, va.y)
        p5, l5, u5 = b5.predict_with_interval(te.X, len(CSV_AVAILABLE_FEATURES))
        self.assertEqual(p5.shape, te.y.shape)
        self.assertEqual(l5.shape, te.y.shape)
        self.assertEqual(u5.shape, te.y.shape)
        
        # B6. GBDT
        b6 = GBDTLearnedModel(candidate_params=[{"max_iter": 10, "learning_rate": 0.1, "max_depth": 3, "min_samples_leaf": 5}])
        b6.fit(tr.X, tr.y, va.X, va.y)
        p6, l6, u6 = b6.predict_with_interval(te.X, len(CSV_AVAILABLE_FEATURES))
        self.assertEqual(p6.shape, te.y.shape)

    def test_metrics_and_behavioural_dimensions(self) -> None:
        y_true = np.array([[1.0, -2.0, 0.0], [3.0, 4.0, -1.0]])
        y_pred = np.array([[0.5, -1.5, 0.0], [2.0, -4.0, -0.5]])
        feats = ["dst_port_diversity", "syn_count", "iat_mean"]
        
        rep = compute_metrics(y_true, y_pred, feats, model_name="TestModel")
        self.assertAlmostEqual(rep.delta_mae, float(np.mean(np.abs(y_true - y_pred))))
        self.assertGreater(rep.directional_accuracy, 0.0)
        self.assertEqual(rep.behavioural_directional_accuracy["destination_diversity"], "UNAVAILABLE")
        self.assertIn("port_diversity", rep.behavioural_directional_accuracy)

    def test_victory_criterion_evaluator(self) -> None:
        # Construct mock reports
        cand_global = MetricReport("Cand", 1.0, 2.0, 0.8, 0.8, {}, "N/A", {}, 100, 15)
        base_global = MetricReport("Base", 2.0, 3.0, 0.6, 0.6, {}, "N/A", {}, 100, 15)
        
        cand_blocks = [MetricReport("Cand", 1.0, 2.0, 0.8, 0.8, {}, "N/A", {}, 50, 15) for _ in range(4)]
        base_blocks = [MetricReport("Base", 2.0, 3.0, 0.6, 0.6, {}, "N/A", {}, 50, 15) for _ in range(4)]
        
        vc_pass = evaluate_victory_criterion(cand_global, base_global, cand_blocks, base_blocks)
        self.assertEqual(vc_pass.status, "PASS")
        
        # Mixed case
        cand_blocks_mixed = [MetricReport("Cand", 3.0, 4.0, 0.5, 0.5, {}, "N/A", {}, 50, 15) for _ in range(4)]
        vc_mixed = evaluate_victory_criterion(cand_global, base_global, cand_blocks_mixed, base_blocks)
        self.assertEqual(vc_mixed.status, "MIXED")


if __name__ == "__main__":
    unittest.main()
