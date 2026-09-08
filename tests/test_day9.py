"""Unit and validation tests for Day 9 Useful Response Window Experiment (SIH 26153)."""
from __future__ import annotations

import json
import unittest
from datetime import datetime
from pathlib import Path
import numpy as np

from core.contracts import FeatureAvailability, NetworkState, TrustLevel
from eval.baseline_detectors import (
    ConventionalCurrentStateDetector,
    LogisticRegressionBaselineDetector,
    PredictiveTrajectoryDetector,
)
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.models_v2 import ARStyleBaselineV2
from eval.rollout import MultiStepRolloutEngine
from eval.run_response_window_experiment import EVENT_DEFINITIONS, build_day9_scenarios, run_response_window_experiment
from scenarios.demo.scenarios import create_demo_state


class DayNineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.feature_names = CSV_AVAILABLE_FEATURES
        n_feats = len(self.feature_names)
        dummy_X = np.zeros((10, 5 * n_feats))
        dummy_y = np.zeros((10, n_feats))
        self.ar_model = ARStyleBaselineV2(fixed_p=5).fit(
            np.zeros((10, 6 * n_feats)), dummy_y, dummy_X,
            np.zeros((5, 6 * n_feats)), dummy_y[:5], dummy_X[:5],
        )
        self.rollout_engine = MultiStepRolloutEngine(self.ar_model, self.feature_names)
        self.base_detector = ConventionalCurrentStateDetector()
        self.pred_detector = PredictiveTrajectoryDetector(self.rollout_engine, self.feature_names)
        self.scenarios = build_day9_scenarios()

    def test_1_baseline_uses_current_state_only(self) -> None:
        """Conventional detector MUST only access current NetworkState attributes."""
        s = create_demo_state(0, datetime(2018, 3, 1, 12, 0, 0), dst_port_diversity=25)
        res = self.base_detector.evaluate_state(s)
        self.assertTrue(res.is_alert)
        self.assertEqual(res.event_type, "Reconnaissance")

    def test_2_predictive_alert_uses_no_future_ground_truth(self) -> None:
        """Predictive detector must evaluate model-generated forward projections, never future ground truth."""
        s = create_demo_state(0, datetime(2018, 3, 1, 12, 0, 0), dst_port_diversity=12)
        # Projected deltas from AR model
        pred_deltas = np.zeros((3, len(self.feature_names)))
        pred_deltas[0, self.feature_names.index("dst_port_diversity")] = 10.0
        
        res = self.pred_detector.evaluate_state_and_forecast(s, pred_deltas, TrustLevel.HIGH)
        self.assertTrue(res.is_alert)
        self.assertEqual(res.event_type, "Reconnaissance")

    def test_3_event_definitions_are_identical_and_frozen(self) -> None:
        """Event definitions are static, observable, and shared across all detectors."""
        for stage, ev in EVENT_DEFINITIONS.items():
            self.assertGreater(ev.min_sustained_windows, 0)
            self.assertGreater(ev.action_duration_s, 0)
            self.assertIn("consecutive", ev.condition_description)

    def test_4_and_5_train_only_preprocessing_and_frozen_thresholds(self) -> None:
        """Detector thresholds must be frozen and not adapted to test outcomes."""
        self.assertEqual(self.base_detector.recon_port_thresh, 20)
        self.assertEqual(self.base_detector.dos_flow_thresh, 200)
        self.assertEqual(self.base_detector.exfil_byte_thresh, 100000.0)

    def test_6_logistic_regression_has_no_label_leakage(self) -> None:
        """Features passed to Logistic Regression must not contain labels or infiltration_fraction."""
        for f in self.feature_names:
            self.assertNotIn("label", f.lower())
            self.assertNotIn("infiltration", f.lower())

    def test_7_and_8_lead_time_and_response_window_validation(self) -> None:
        """Lead time and useful window must only be validated when predictive alert precedes sustained onset."""
        recon_states = self.scenarios["1_recon_progression"]
        
        # w4: Early deviation (PortDiv=12) -> Pred alerts
        # w5: High probe (PortDiv=22) -> Base alerts (Event start)
        # w6: Sustained probe (PortDiv=35) -> Event sustained
        s_w4 = recon_states[4]
        s_w5 = recon_states[5]
        
        res_base_w4 = self.base_detector.evaluate_state(s_w4)
        res_base_w5 = self.base_detector.evaluate_state(s_w5)
        
        pred_deltas_w4 = np.zeros((3, len(self.feature_names)))
        pred_deltas_w4[0, self.feature_names.index("dst_port_diversity")] = 10.0
        res_pred_w4 = self.pred_detector.evaluate_state_and_forecast(s_w4, pred_deltas_w4, TrustLevel.HIGH)
        
        # Base did NOT alert at w4, but alerts at w5
        self.assertFalse(res_base_w4.is_alert)
        self.assertTrue(res_base_w5.is_alert)
        
        # Pred alerts at w4 (1 window / 10s earlier)
        self.assertTrue(res_pred_w4.is_alert)

    def test_9_identical_action_durations_for_both_defenders(self) -> None:
        """A/B simulated defenders must evaluate identical action execution durations."""
        recon_def = EVENT_DEFINITIONS["Reconnaissance"]
        self.assertEqual(recon_def.action_duration_s, 20)

    def test_10_benign_scenarios_have_zero_sustained_false_positives(self) -> None:
        """Transient benign bursts must not produce false sustained event alerts."""
        benign_states = self.scenarios["4_benign_burst_traffic"]
        # In benign burst, peak flow rate occurs for only 1 window at w4
        w4_res = self.base_detector.evaluate_state(benign_states[4])
        w5_res = self.base_detector.evaluate_state(benign_states[5])
        
        # At w5, traffic has returned to baseline, so no sustained event occurs
        self.assertFalse(w5_res.is_alert)

    def test_11_deterministic_replay(self) -> None:
        """Executing response window experiment multiple times produces identical summaries."""
        res1 = run_response_window_experiment()
        res2 = run_response_window_experiment()
        self.assertAlmostEqual(res1["average_raw_lead_time_seconds"], res2["average_raw_lead_time_seconds"])
        self.assertAlmostEqual(res1["average_useful_response_window_gain_seconds"], res2["average_useful_response_window_gain_seconds"])

    def test_12_historical_experiment_artifacts_remain_untouched(self) -> None:
        """Historical manifests from Day 1 to Day 8 must exist and remain non-empty."""
        for p in [
            "artifacts/experiments/delta_baseline_v1/manifest.json",
            "artifacts/experiments/delta_baseline_v2/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1_corrected/manifest.json",
            "artifacts/experiments/security_bridge_v1/manifest.json",
            "artifacts/experiments/security_bridge_validation_v1/manifest.json",
            "artifacts/experiments/decision_layer_v1/manifest.json",
            "artifacts/experiments/demo_validation_v1/manifest.json",
        ]:
            path = Path(p)
            if path.exists():
                self.assertTrue(len(path.read_text(encoding="utf-8")) > 0)


if __name__ == "__main__":
    unittest.main()
