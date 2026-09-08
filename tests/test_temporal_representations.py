"""
Unit and Leakage Test Suite for Temporal Representations & Feature Observability
SIH PS 26153

Tests:
1. Chronological ordering preservation.
2. Truncation invariance (representation at t unchanged when future is removed).
3. No future-state access during operational feature calculation.
4. Label independence (representations computed without any label metadata).
5. Deterministic replay (identical sequence yields identical features).
6. Buffer/reset isolation (reset clears all state, deltas, and pending forecasts).
7. Causal warm-up (safe handling when history < min_history, zero division guards).
8. Post-hoc residual isolation (residuals evaluated after forecast, never fed back).
9. Reproducible calibration (pre-test data 04:00-08:00 yields deterministic floors).
10. Complete schema and representation completeness across all 6 families.
"""

import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
import numpy as np

from core.contracts import FeatureAvailability, NetworkState, Source
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.rollout import MultiStepRolloutEngine
from runtime.train_authoritative_model import load_ar_model
from eval.study_temporal_representations import (
    CausalTemporalRepresentationExtractor,
    CalibrationParameters,
    calibrate_on_pre_test_data,
)


def make_dummy_state(timestamp_str: str, base_val: float = 10.0) -> NetworkState:
    """Constructs a deterministic synthetic NetworkState for causal testing."""
    dt = datetime.fromisoformat(timestamp_str)
    avail = {f: FeatureAvailability.AVAILABLE for f in CSV_AVAILABLE_FEATURES}
    return NetworkState(
        window_id=f"win_{dt.strftime('%H%M%S')}",
        timestamp_start=dt,
        timestamp_end=dt + timedelta(seconds=10),
        window_duration_s=10.0,
        flow_count=int(base_val),
        packet_rate=base_val * 2.0,
        byte_rate=base_val * 100.0,
        mean_flow_duration=1.5,
        dst_port_diversity=int(max(1.0, base_val / 5.0)),
        syn_count=int(base_val * 0.1),
        ack_count=int(base_val * 0.8),
        rst_count=int(base_val * 0.05),
        syn_ratio=0.1,
        rst_ratio=0.05,
        iat_mean=0.25,
        iat_std=0.05,
        iat_skew=None,
        pkt_size_mean=500.0,
        pkt_size_std=50.0,
        byte_variance=2500.0,
        src_ip_diversity=None,
        dst_ip_diversity=None,
        src_port_diversity=None,
        fan_out=None,
        internal_ratio=None,
        east_west_count=None,
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
        session_id="test-session",
        provenance_hash="0" * 64,
        feature_availability=avail,
    )


class TestTemporalRepresentations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Build a small deterministic synthetic calibration series (60 states)
        t0 = datetime(2018, 3, 1, 4, 0, 0, tzinfo=timezone.utc)
        cls.synthetic_calib_states = [
            make_dummy_state((t0 + timedelta(seconds=10 * i)).isoformat(), base_val=20.0 + (i % 5))
            for i in range(60)
        ]
        cls.calib = calibrate_on_pre_test_data(cls.synthetic_calib_states, window_length=30, min_history=5)
        
        # Authoritative AR(5) rollout engine
        model_dir = Path("artifacts/models/ar5_authoritative")
        cls.ar_model, _ = load_ar_model(model_dir)
        cls.rollout_engine = MultiStepRolloutEngine(ar_model=cls.ar_model, feature_names=CSV_AVAILABLE_FEATURES)

    def test_01_chronological_ordering_preservation(self):
        """Test 1: Extractor preserves monotonic chronological timestamps."""
        extractor = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)
        t0 = datetime(2018, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
        states = [
            make_dummy_state((t0 + timedelta(seconds=10 * i)).isoformat(), base_val=15.0 + i)
            for i in range(10)
        ]
        recs = [extractor.process_window(st, i) for i, st in enumerate(states)]
        timestamps = [r["timestamp"] for r in recs]
        self.assertEqual(len(timestamps), 10)
        for i in range(1, len(timestamps)):
            self.assertGreater(timestamps[i], timestamps[i - 1])

    def test_02_truncation_invariance(self):
        """
        Test 2: Truncation invariance.
        Representation computed for window k must be mathematically identical whether
        the stream ends at k or continues to K (K > k).
        """
        t0 = datetime(2018, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
        full_states = [
            make_dummy_state((t0 + timedelta(seconds=10 * i)).isoformat(), base_val=10.0 + (i * 2.5) % 15)
            for i in range(25)
        ]
        
        # Run on full sequence
        ext_full = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)
        recs_full = [ext_full.process_window(st, i) for i, st in enumerate(full_states)]

        # Run on truncated sequence (first 15 states)
        ext_trunc = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)
        recs_trunc = [ext_trunc.process_window(st, i) for i, st in enumerate(full_states[:15])]

        self.assertEqual(len(recs_trunc), 15)
        for k in range(15):
            # All level values must match exactly
            for f in CSV_AVAILABLE_FEATURES:
                self.assertEqual(recs_full[k]["fam0_levels"][f], recs_trunc[k]["fam0_levels"][f])
                self.assertEqual(recs_full[k]["fam1_diffs"][f], recs_trunc[k]["fam1_diffs"][f])
                self.assertAlmostEqual(recs_full[k]["fam1_norm_diffs"][f], recs_trunc[k]["fam1_norm_diffs"][f], places=9)
                self.assertAlmostEqual(recs_full[k]["fam2_accel"][f], recs_trunc[k]["fam2_accel"][f], places=9)
            # Burst descriptors must match
            for bk in recs_full[k]["fam3_burst"]:
                self.assertAlmostEqual(recs_full[k]["fam3_burst"][bk], recs_trunc[k]["fam3_burst"][bk], places=9)
            # Synchrony descriptors must match
            for sk in recs_full[k]["fam4_synchrony"]:
                self.assertAlmostEqual(recs_full[k]["fam4_synchrony"][sk], recs_trunc[k]["fam4_synchrony"][sk], places=9)

    def test_03_no_future_state_access(self):
        """
        Test 3: Mutating future states in the input array has zero impact on earlier representations.
        """
        t0 = datetime(2018, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
        states_a = [
            make_dummy_state((t0 + timedelta(seconds=10 * i)).isoformat(), base_val=12.0)
            for i in range(10)
        ]
        states_b = [
            make_dummy_state((t0 + timedelta(seconds=10 * i)).isoformat(), base_val=12.0)
            for i in range(10)
        ]
        # Dramatically alter the future state at index 9
        states_b[9] = make_dummy_state((t0 + timedelta(seconds=90)).isoformat(), base_val=999999.0)

        ext_a = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)
        ext_b = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)

        recs_a = [ext_a.process_window(st, i) for i, st in enumerate(states_a)]
        recs_b = [ext_b.process_window(st, i) for i, st in enumerate(states_b)]

        # For windows 0..8, representations MUST be bitwise identical
        for k in range(9):
            self.assertEqual(recs_a[k]["fam0_levels"]["flow_count"], recs_b[k]["fam0_levels"]["flow_count"])
            self.assertEqual(recs_a[k]["fam1_diffs"]["flow_count"], recs_b[k]["fam1_diffs"]["flow_count"])
            self.assertEqual(recs_a[k]["fam4_synchrony"]["sync_flow_count_byte_rate"], recs_b[k]["fam4_synchrony"]["sync_flow_count_byte_rate"])

    def test_04_label_independence(self):
        """
        Test 4: Extractor is completely oblivious to attack labels / scenarios.
        No labels exist on NetworkState, verifying pure telemetry evaluation.
        """
        st = make_dummy_state("2018-03-01T09:00:00+00:00", base_val=25.0)
        self.assertFalse(hasattr(st, "label"))
        self.assertFalse(hasattr(st, "is_attack"))
        self.assertFalse(hasattr(st, "attack_type"))
        extractor = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)
        rec = extractor.process_window(st, 0)
        self.assertIsNotNone(rec)
        self.assertIn("dst_port_diversity", rec["fam0_levels"])

    def test_05_deterministic_replay(self):
        """Test 5: Processing the identical state sequence twice produces bitwise identical features."""
        t0 = datetime(2018, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
        states = [
            make_dummy_state((t0 + timedelta(seconds=10 * i)).isoformat(), base_val=10.0 + i)
            for i in range(12)
        ]
        ext1 = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)
        ext2 = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)

        recs1 = [ext1.process_window(st, i) for i, st in enumerate(states)]
        recs2 = [ext2.process_window(st, i) for i, st in enumerate(states)]

        for r1, r2 in zip(recs1, recs2):
            self.assertEqual(r1["fam0_levels"], r2["fam0_levels"])
            self.assertEqual(r1["fam1_diffs"], r2["fam1_diffs"])
            self.assertEqual(r1["fam1_norm_diffs"], r2["fam1_norm_diffs"])
            self.assertEqual(r1["fam2_accel"], r2["fam2_accel"])
            self.assertEqual(r1["fam3_burst"], r2["fam3_burst"])
            self.assertEqual(r1["fam4_synchrony"], r2["fam4_synchrony"])
            self.assertEqual(r1["fam5_residuals"], r2["fam5_residuals"])

    def test_06_buffer_reset_isolation(self):
        """Test 6: reset() clears all internal rolling buffers and pending forecasts completely."""
        extractor = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)
        t0 = datetime(2018, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
        states = [
            make_dummy_state((t0 + timedelta(seconds=10 * i)).isoformat(), base_val=10.0 + i)
            for i in range(15)
        ]
        for i, st in enumerate(states):
            extractor.process_window(st, i)

        self.assertGreater(len(extractor.state_history), 0)
        self.assertGreater(len(extractor.delta_history), 0)

        extractor.reset()

        self.assertEqual(len(extractor.state_history), 0)
        self.assertEqual(len(extractor.delta_history), 0)
        self.assertIsNone(extractor.pending_forecast)
        for f in CSV_AVAILABLE_FEATURES:
            self.assertEqual(len(extractor.robust_z_history[f]), 0)

    def test_07_causal_warmup_and_guards(self):
        """Test 7: During warm-up (history < min_history), representations do not crash or produce NaNs."""
        extractor = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)
        t0 = datetime(2018, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
        states = [
            make_dummy_state((t0 + timedelta(seconds=10 * i)).isoformat(), base_val=10.0)
            for i in range(4)  # Fewer than min_history (5)
        ]
        for i, st in enumerate(states):
            rec = extractor.process_window(st, i)
            for f in CSV_AVAILABLE_FEATURES:
                self.assertFalse(np.isnan(rec["fam0_levels"][f]))
                self.assertFalse(np.isnan(rec["fam1_norm_diffs"][f]))
                self.assertFalse(np.isinf(rec["fam1_norm_diffs"][f]))
                self.assertFalse(np.isnan(rec["fam2_norm_accel"][f]))
            for k, v in rec["fam3_burst"].items():
                self.assertFalse(np.isnan(v))
            for k, v in rec["fam4_synchrony"].items():
                self.assertFalse(np.isnan(v))

    def test_08_post_hoc_residual_isolation(self):
        """
        Test 8: Residual e_t is evaluated post-hoc after forecast commit.
        Residuals are never fed back into the AR(5) forecast input buffer.
        """
        extractor = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)
        t0 = datetime(2018, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
        # Need at least p=5 states before AR(5) can issue forecast
        states = [
            make_dummy_state((t0 + timedelta(seconds=10 * i)).isoformat(), base_val=15.0)
            for i in range(8)
        ]
        recs = [extractor.process_window(st, i) for i, st in enumerate(states)]

        # Window 0 has zero residual norm because no prior forecast was pending
        self.assertEqual(recs[0]["fam5_residuals"]["residual_norm"], 0.0)

        # Window 1 has post-hoc residual evaluated from forecast emitted at window 0
        self.assertIn("res_flow_count", recs[1]["fam5_residuals"])
        self.assertIn("residual_norm", recs[1]["fam5_residuals"])

        # Verify state history only stores actual observations, not forecast residuals
        for item in extractor.state_history:
            self.assertIn("flow_count", item)
            self.assertNotIn("res_flow_count", item)

    def test_09_reproducible_calibration(self):
        """Test 9: Pre-test calibration produces deterministic, valid scale floors."""
        calib1 = calibrate_on_pre_test_data(self.synthetic_calib_states, window_length=30, min_history=5)
        calib2 = calibrate_on_pre_test_data(self.synthetic_calib_states, window_length=30, min_history=5)

        for f in CSV_AVAILABLE_FEATURES:
            self.assertEqual(calib1.scale_floors[f], calib2.scale_floors[f])
            self.assertEqual(calib1.ref_means[f], calib2.ref_means[f])
            self.assertGreater(calib1.scale_floors[f], 0.0)

    def test_10_schema_completeness(self):
        """Test 10: Extracted records provide complete coverage of declared features."""
        extractor = CausalTemporalRepresentationExtractor(self.calib, self.rollout_engine)
        t0 = datetime(2018, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
        states = [
            make_dummy_state((t0 + timedelta(seconds=10 * i)).isoformat(), base_val=20.0 + i)
            for i in range(10)
        ]
        recs = [extractor.process_window(st, i) for i, st in enumerate(states)]
        last_rec = recs[-1]

        # 15 raw levels
        self.assertEqual(len(last_rec["fam0_levels"]), len(CSV_AVAILABLE_FEATURES))
        # 15 diffs, 15 norm diffs
        self.assertEqual(len(last_rec["fam1_diffs"]), len(CSV_AVAILABLE_FEATURES))
        self.assertEqual(len(last_rec["fam1_norm_diffs"]), len(CSV_AVAILABLE_FEATURES))
        # 15 accels, 15 norm accels
        self.assertEqual(len(last_rec["fam2_accel"]), len(CSV_AVAILABLE_FEATURES))
        self.assertEqual(len(last_rec["fam2_norm_accel"]), len(CSV_AVAILABLE_FEATURES))
        # Burst descriptors
        self.assertIn("dst_port_diversity_run_length", last_rec["fam3_burst"])
        self.assertIn("flow_count_duty_cycle", last_rec["fam3_burst"])
        self.assertIn("byte_rate_quiet_duration", last_rec["fam3_burst"])
        # Synchrony
        self.assertIn("sync_flow_count_byte_rate", last_rec["fam4_synchrony"])
        self.assertIn("mahalanobis_volume_vector", last_rec["fam4_synchrony"])


if __name__ == "__main__":
    unittest.main()
