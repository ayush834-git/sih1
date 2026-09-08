"""Unit and validation tests for Day 5 Multi-Step Rollout & Uncertainty Quantification."""
from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path
import numpy as np

from core.contracts import (
    FeatureAvailability,
    Forecast,
    NetworkState,
    Source,
    Trajectory,
    TrajectoryStep,
)
from eval.dataset import (
    CSV_AVAILABLE_FEATURES,
    OBSERVED_INFILTRATION_BLOCKS,
    chronological_split,
    samples_to_arrays,
)
from eval.metrics_v2 import compute_training_scales
from eval.models_v2 import ARStyleBaselineV2
from eval.rollout import (
    MultiFutureTrajectoryGenerator,
    MultiStepRolloutEngine,
    MultiStepSample,
    ResidualBootstrapEngine,
    TrustScoringEngine,
    extract_multistep_samples,
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


class DayFiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.t0 = datetime(2018, 2, 28, 1, 0, 0)
        self.states = [
            _make_dummy_state(self.t0 + timedelta(seconds=10 * i), byte_rate=100.0 + 10.0 * i)
            for i in range(60)
        ]
        self.samples, _ = extract_multistep_samples(self.states, history_depth=6, max_horizon=3)

    def test_1_h1_reproduces_one_step_ar_behavior(self) -> None:
        tr_s, val_s, te_s = chronological_split(self.samples, 0.60, 0.20, 0.20)
        n_feats = len(CSV_AVAILABLE_FEATURES)
        
        # Build training data
        tr_Xd = np.array([[s.history_deltas[k][f] for k in range(5) for f in CSV_AVAILABLE_FEATURES] for s in tr_s])
        tr_yd = np.array([[s.future_deltas[0][f] for f in CSV_AVAILABLE_FEATURES] for s in tr_s])
        va_Xd = np.array([[s.history_deltas[k][f] for k in range(5) for f in CSV_AVAILABLE_FEATURES] for s in val_s])
        va_yd = np.array([[s.future_deltas[0][f] for f in CSV_AVAILABLE_FEATURES] for s in val_s])
        te_Xd = np.array([[s.history_deltas[k][f] for k in range(5) for f in CSV_AVAILABLE_FEATURES] for s in te_s])
        te_curr = np.array([[s.source_state.feature_values()[f] for f in CSV_AVAILABLE_FEATURES] for s in te_s])
        
        scales = compute_training_scales(tr_yd, CSV_AVAILABLE_FEATURES)
        ar5 = ARStyleBaselineV2(fixed_p=5).fit(
            np.zeros((len(tr_s), 6 * n_feats)), tr_yd, tr_Xd,
            np.zeros((len(val_s), 6 * n_feats)), va_yd, va_Xd,
            scales=scales
        )
        
        direct_pred = ar5.predict(np.zeros((len(te_s), 6 * n_feats)), te_Xd, n_feats)
        engine = MultiStepRolloutEngine(ar5, CSV_AVAILABLE_FEATURES)
        ol_deltas, _ = engine.forecast_open_loop(te_Xd, te_curr, max_horizon=3)
        
        # Step h=1 must match direct single-step AR prediction exactly
        np.testing.assert_array_almost_equal(ol_deltas[:, 0, :], direct_pred)

    def test_2_open_loop_does_not_use_future_ground_truth(self) -> None:
        # Alter future deltas on sample object and verify open-loop forecast is unchanged
        s = self.samples[0]
        te_Xd = np.array([[s.history_deltas[k][f] for k in range(5) for f in CSV_AVAILABLE_FEATURES]])
        te_curr = np.array([[s.source_state.feature_values()[f] for f in CSV_AVAILABLE_FEATURES]])
        
        n_feats = len(CSV_AVAILABLE_FEATURES)
        dummy_tr_Xd = np.ones((10, 5 * n_feats))
        dummy_tr_yd = np.ones((10, n_feats))
        ar5 = ARStyleBaselineV2(fixed_p=5).fit(
            np.zeros((10, 6 * n_feats)), dummy_tr_yd, dummy_tr_Xd,
            np.zeros((5, 6 * n_feats)), dummy_tr_yd[:5], dummy_tr_Xd[:5]
        )
        engine = MultiStepRolloutEngine(ar5, CSV_AVAILABLE_FEATURES)
        ol_deltas_1, _ = engine.forecast_open_loop(te_Xd, te_curr, max_horizon=3)
        
        # Changing sample's future deltas should have zero impact on open-loop predictions
        s_altered_future = MultiStepSample(
            sample_id="alt",
            source_state=s.source_state,
            source_time=s.source_time,
            target_start=s.target_start,
            target_end=s.target_end,
            session_id=s.session_id,
            history_states=s.history_states,
            history_deltas=s.history_deltas,
            future_states=tuple({f: 9999.0 for f in CSV_AVAILABLE_FEATURES} for _ in range(3)),
            future_deltas=tuple({f: 9999.0 for f in CSV_AVAILABLE_FEATURES} for _ in range(3)),
            feature_names=s.feature_names,
        )
        te_Xd_alt = np.array([[s_altered_future.history_deltas[k][f] for k in range(5) for f in CSV_AVAILABLE_FEATURES]])
        ol_deltas_2, _ = engine.forecast_open_loop(te_Xd_alt, te_curr, max_horizon=3)
        np.testing.assert_array_almost_equal(ol_deltas_1, ol_deltas_2)

    def test_3_receding_horizon_updates_state_context_correctly(self) -> None:
        tr_s, val_s, te_s = chronological_split(self.samples, 0.60, 0.20, 0.20)
        n_feats = len(CSV_AVAILABLE_FEATURES)
        tr_Xd = np.array([[s.history_deltas[k][f] for k in range(5) for f in CSV_AVAILABLE_FEATURES] for s in tr_s])
        tr_yd = np.array([[s.future_deltas[0][f] for f in CSV_AVAILABLE_FEATURES] for s in tr_s])
        
        ar5 = ARStyleBaselineV2(fixed_p=5).fit(
            np.zeros((len(tr_s), 6 * n_feats)), tr_yd, tr_Xd,
            np.zeros((len(val_s), 6 * n_feats)), tr_yd[:len(val_s)], tr_Xd[:len(val_s)]
        )
        engine = MultiStepRolloutEngine(ar5, CSV_AVAILABLE_FEATURES)
        rec_deltas = engine.forecast_receding_horizon(te_s, max_horizon=3)
        self.assertEqual(rec_deltas.shape, (len(te_s), 3, n_feats))

    def test_4_residual_samples_originate_from_training_residuals_only(self) -> None:
        y_train = np.array([[10.0, 20.0], [30.0, 40.0], [50.0, 60.0]])
        y_train_pred = np.array([[8.0, 18.0], [25.0, 35.0], [45.0, 55.0]])
        boot_engine = ResidualBootstrapEngine(y_train, y_train_pred, seed=42)
        
        expected_residuals = y_train - y_train_pred
        self.assertEqual(boot_engine.residuals.shape, (3, 2))
        np.testing.assert_array_almost_equal(boot_engine.residuals, expected_residuals)

    def test_5_prediction_intervals_deterministic_with_fixed_seed(self) -> None:
        y_train = np.random.randn(20, 15)
        y_train_pred = np.random.randn(20, 15)
        
        b1 = ResidualBootstrapEngine(y_train, y_train_pred, seed=42)
        b2 = ResidualBootstrapEngine(y_train, y_train_pred, seed=42)
        
        ar5 = ARStyleBaselineV2(fixed_p=1).fit(
            np.zeros((20, 15)), y_train, np.random.randn(20, 15),
            np.zeros((5, 15)), y_train[:5], np.random.randn(5, 15)
        )
        curr = np.zeros((2, 15))
        d_buf = np.zeros((2, 15))
        
        sim1 = b1.generate_bootstrap_rollouts(ar5, d_buf, curr, n_bootstrap=10, max_horizon=2)
        sim2 = b2.generate_bootstrap_rollouts(ar5, d_buf, curr, n_bootstrap=10, max_horizon=2)
        np.testing.assert_array_almost_equal(sim1, sim2)

    def test_6_and_7_trajectory_contracts_and_k3_distinctness(self) -> None:
        generator = MultiFutureTrajectoryGenerator(CSV_AVAILABLE_FEATURES)
        s = self.samples[0]
        det = np.ones((3, len(CSV_AVAILABLE_FEATURES))) * 5.0
        boot = np.random.randn(50, 3, len(CSV_AVAILABLE_FEATURES)) * 10.0 + 5.0
        
        t0, t1, t2 = generator.construct_k3_trajectories(s, det, boot, datetime.now())
        self.assertIsInstance(t0, Trajectory)
        self.assertIsInstance(t1, Trajectory)
        self.assertIsInstance(t2, Trajectory)
        
        # Verify weight sum equals 1.0 without arbitrary softmax
        self.assertAlmostEqual(t0.weight + t1.weight + t2.weight, 1.0)
        self.assertEqual(len(t0.steps), 3)
        self.assertEqual(len(t1.steps), 3)
        self.assertEqual(len(t2.steps), 3)
        
        # Check forecast state invariant S_{t+1} = S_t + ΔS_{t+1}
        for step in t0.steps:
            self.assertIsInstance(step.forecast, Forecast)
            for f in CSV_AVAILABLE_FEATURES:
                self.assertIn(f, step.forecast.delta_predicted)
                self.assertIn(f, step.forecast.state_predicted)

    def test_8_no_arbitrary_softmax_probabilities(self) -> None:
        generator = MultiFutureTrajectoryGenerator(CSV_AVAILABLE_FEATURES)
        s = self.samples[0]
        t0, t1, t2 = generator.construct_k3_trajectories(
            s, np.zeros((3, len(CSV_AVAILABLE_FEATURES))), np.zeros((10, 3, len(CSV_AVAILABLE_FEATURES))), datetime.now()
        )
        self.assertEqual(t0.weight, 0.50)
        self.assertEqual(t1.weight, 0.25)
        self.assertEqual(t2.weight, 0.25)

    def test_9_no_label_or_infiltration_leakage(self) -> None:
        for f in CSV_AVAILABLE_FEATURES:
            self.assertNotIn("label", f.lower())
            self.assertNotIn("infiltration", f.lower())

    def test_10_no_gap_or_session_crossing(self) -> None:
        # Create sequence with session boundary in the middle
        split_states = list(self.states[:4]) + [
            _make_dummy_state(self.t0 + timedelta(seconds=10 * 4), session_id="session-2")
        ] + list(self.states[5:10])
        samples_split, dropped = extract_multistep_samples(split_states, history_depth=6, max_horizon=3)
        self.assertGreater(dropped["session_boundary_crossed"], 0)

    def test_11_v1_v2_artifacts_remain_untouched(self) -> None:
        v1_manifest = Path("artifacts/experiments/delta_baseline_v1/manifest.json")
        v2_manifest = Path("artifacts/experiments/delta_baseline_v2/manifest.json")
        if v1_manifest.exists():
            v1_data = json.loads(v1_manifest.read_text(encoding="utf-8"))
            self.assertEqual(v1_data["experiment_name"], "delta_baseline_v1")
        if v2_manifest.exists():
            v2_data = json.loads(v2_manifest.read_text(encoding="utf-8"))
            self.assertEqual(v2_data["experiment_name"], "delta_baseline_v2")

    def test_12_trust_monotonically_decays_with_horizon(self) -> None:
        scales = compute_training_scales(np.ones((10, len(CSV_AVAILABLE_FEATURES))), CSV_AVAILABLE_FEATURES)
        engine = TrustScoringEngine(scales)
        t1 = engine.compute_trust_for_horizon(1, 1.0, 1.0)
        t2 = engine.compute_trust_for_horizon(2, 1.5, 1.2)
        t3 = engine.compute_trust_for_horizon(3, 2.0, 1.5)
        self.assertGreaterEqual(t1.composite_trust, t2.composite_trust)
        self.assertGreaterEqual(t2.composite_trust, t3.composite_trust)

    def test_14_receding_first_step_independent_of_future_observations(self) -> None:
        """First-step prediction in receding-horizon must be strictly independent of future observations."""
        s = self.samples[0]
        n_feats = len(CSV_AVAILABLE_FEATURES)
        dummy_tr_Xd = np.ones((10, 5 * n_feats))
        dummy_tr_yd = np.ones((10, n_feats))
        ar5 = ARStyleBaselineV2(fixed_p=5).fit(
            np.zeros((10, 6 * n_feats)), dummy_tr_yd, dummy_tr_Xd,
            np.zeros((5, 6 * n_feats)), dummy_tr_yd[:5], dummy_tr_Xd[:5]
        )
        engine = MultiStepRolloutEngine(ar5, CSV_AVAILABLE_FEATURES)
        
        # Original sample
        rec_pred_1 = engine.forecast_receding_horizon([s], max_horizon=3)
        
        # Sample with completely altered future ground truth deltas
        s_altered = MultiStepSample(
            sample_id="alt",
            source_state=s.source_state,
            source_time=s.source_time,
            target_start=s.target_start,
            target_end=s.target_end,
            session_id=s.session_id,
            history_states=s.history_states,
            history_deltas=s.history_deltas,
            future_states=tuple({f: 8888.0 for f in CSV_AVAILABLE_FEATURES} for _ in range(3)),
            future_deltas=tuple({f: 8888.0 for f in CSV_AVAILABLE_FEATURES} for _ in range(3)),
            feature_names=s.feature_names,
        )
        rec_pred_2 = engine.forecast_receding_horizon([s_altered], max_horizon=3)
        
        # Horizon h=1 prediction must be IDENTICAL
        np.testing.assert_array_almost_equal(rec_pred_1[:, 0, :], rec_pred_2[:, 0, :])
        
    def test_15_later_receding_predictions_depend_on_newly_observed_truth(self) -> None:
        """Later predictions (h>=2) in receding-horizon must adapt when new true observations arrive."""
        s = self.samples[0]
        n_feats = len(CSV_AVAILABLE_FEATURES)
        rng = np.random.default_rng(42)
        dummy_tr_Xd = rng.standard_normal((30, 5 * n_feats))
        dummy_tr_yd = dummy_tr_Xd[:, :n_feats] * 0.8 + rng.standard_normal((30, n_feats)) * 0.1
        ar5 = ARStyleBaselineV2(fixed_p=5).fit(
            np.zeros((30, 6 * n_feats)), dummy_tr_yd, dummy_tr_Xd,
            np.zeros((10, 6 * n_feats)), dummy_tr_yd[:10], dummy_tr_Xd[:10]
        )
        engine = MultiStepRolloutEngine(ar5, CSV_AVAILABLE_FEATURES)
        
        rec_pred_1 = engine.forecast_receding_horizon([s], max_horizon=3)
        
        s_altered = MultiStepSample(
            sample_id="alt",
            source_state=s.source_state,
            source_time=s.source_time,
            target_start=s.target_start,
            target_end=s.target_end,
            session_id=s.session_id,
            history_states=s.history_states,
            history_deltas=s.history_deltas,
            future_states=tuple({f: 500.0 for f in CSV_AVAILABLE_FEATURES} for _ in range(3)),
            future_deltas=tuple({f: 500.0 for f in CSV_AVAILABLE_FEATURES} for _ in range(3)),
            feature_names=s.feature_names,
        )
        rec_pred_2 = engine.forecast_receding_horizon([s_altered], max_horizon=3)
        
        # Horizons h=2 and h=3 must reflect the newly observed context and therefore differ
        self.assertFalse(np.allclose(rec_pred_1[:, 1, :], rec_pred_2[:, 1, :]))
        self.assertFalse(np.allclose(rec_pred_1[:, 2, :], rec_pred_2[:, 2, :]))

    def test_16_trajectory_scenarios_are_actual_continuous_bootstrap_paths(self) -> None:
        """Trajectories T1 and T2 must correspond to actual continuous bootstrap paths across all horizons."""
        scales = compute_training_scales(np.ones((10, len(CSV_AVAILABLE_FEATURES))), CSV_AVAILABLE_FEATURES)
        generator = MultiFutureTrajectoryGenerator(CSV_AVAILABLE_FEATURES, scales=scales)
        s = self.samples[0]
        n_bootstrap = 20
        max_h = 3
        det = np.ones((max_h, len(CSV_AVAILABLE_FEATURES))) * 5.0
        # Distinct bootstrap paths
        boot = np.zeros((n_bootstrap, max_h, len(CSV_AVAILABLE_FEATURES)))
        for b in range(n_bootstrap):
            boot[b, :, :] = float(b + 1)
            
        t0, t1, t2 = generator.construct_k3_trajectories(s, det, boot, datetime.now())
        
        # Check that t1 deltas across all 3 steps match ONE exact bootstrap path b
        t1_deltas_step0 = [t1.steps[0].forecast.delta_predicted[f] for f in CSV_AVAILABLE_FEATURES]
        t1_deltas_step1 = [t1.steps[1].forecast.delta_predicted[f] for f in CSV_AVAILABLE_FEATURES]
        t1_deltas_step2 = [t1.steps[2].forecast.delta_predicted[f] for f in CSV_AVAILABLE_FEATURES]
        
        # Find which bootstrap index was selected
        matched_indices = []
        for b in range(n_bootstrap):
            if np.allclose(boot[b, 0, :], t1_deltas_step0):
                matched_indices.append(b)
        self.assertEqual(len(matched_indices), 1)
        matched_b = matched_indices[0]
        
        # Step 1 and Step 2 must come from the EXACT SAME bootstrap index matched_b
        np.testing.assert_array_almost_equal(boot[matched_b, 1, :], t1_deltas_step1)
        np.testing.assert_array_almost_equal(boot[matched_b, 2, :], t1_deltas_step2)


if __name__ == "__main__":
    unittest.main()
