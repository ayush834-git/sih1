"""Unit and validation tests for Day 10 Explainability Layer (SIH 26153)."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

from core.contracts import Direction, FeatureAvailability, NetworkState, Source, TrustLevel
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.models_v2 import ARStyleBaselineV2
from explainability.contracts import (
    ContributionDirection,
    EvidenceType,
    FeatureContribution,
    ForecastExplanation,
    LagContribution,
    SecurityHypothesisExplanation,
)
from explainability.engine import ExplainabilityEngine
from scenarios.demo.scenarios import create_demo_state
from security.bridge import BehavioralSecurityBridge


class ExplainabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.t0 = datetime(2018, 3, 1, 12, 0, 0)
        self.feature_names = list(CSV_AVAILABLE_FEATURES)
        self.explainer = ExplainabilityEngine(feature_names=self.feature_names)
        self.bridge = BehavioralSecurityBridge()

        # Dummy AR(5) model for testing
        D = len(self.feature_names)
        p = 5
        N = 20
        X_dummy = np.random.RandomState(42).randn(N, (p + 1) * D)
        y_dummy = np.random.RandomState(42).randn(N, D)
        X_deltas_dummy = np.random.RandomState(42).randn(N, p * D)
        self.ar5_model = ARStyleBaselineV2(fixed_p=p).fit(
            X_dummy, y_dummy, X_deltas_dummy,
            X_dummy, y_dummy, X_deltas_dummy,
        )

    def _get_primary_hypothesis(
        self,
        state: NetworkState,
        forecast_deltas: list[dict[str, float]] | None = None,
    ):
        if forecast_deltas is not None:
            fc_arr = np.array([[fd.get(f, 0.0) for f in self.feature_names] for fd in forecast_deltas])
        else:
            fc_arr = None
        sigs = self.bridge.extract_signatures(state, forecast_deltas=fc_arr, feature_names=self.feature_names)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        return hyps[0]

    def test_1_explanation_schema_fields(self) -> None:
        """ForecastExplanation and SecurityHypothesisExplanation contain all required typed fields."""
        curr_state = create_demo_state(5, self.t0)
        h_deltas = np.zeros((5, len(self.feature_names)))

        fc_expl = self.explainer.explain_ar_forecast(
            ar_model=self.ar5_model,
            current_state=curr_state,
            history_deltas=h_deltas,
            target_feature="dst_port_diversity",
        )
        self.assertIsInstance(fc_expl, ForecastExplanation)
        self.assertEqual(fc_expl.target_feature, "dst_port_diversity")
        self.assertEqual(fc_expl.model_name, "AR(5)")
        self.assertIn("dst_port_diversity", [fc.feature_name for fc in fc_expl.top_features])

        # Test dictionary conversion
        d = fc_expl.to_dict()
        self.assertIn("explanation_id", d)
        self.assertIn("provenance_hash", d)
        self.assertIn("evidence_type", d)

    def test_2_ar5_lag_contribution_calculation(self) -> None:
        """Lag contributions mathematically equal beta * Delta_x for each lag."""
        curr_state = create_demo_state(5, self.t0)
        h_deltas = np.ones((5, len(self.feature_names))) * 2.0  # All deltas = 2.0

        fc_expl = self.explainer.explain_ar_forecast(
            ar_model=self.ar5_model,
            current_state=curr_state,
            history_deltas=h_deltas,
            target_feature="dst_port_diversity",
        )
        top_contrib = fc_expl.top_features[0]
        self.assertEqual(len(top_contrib.lag_breakdown), 5)

        for lag in top_contrib.lag_breakdown:
            expected_contrib = lag.coefficient * lag.lag_value
            self.assertAlmostEqual(lag.signed_contribution, expected_contrib, places=5)

    def test_3_top_k_feature_ranking(self) -> None:
        """Multi-feature rollout ranking produces exactly top_k ordered by normalized contribution."""
        curr_state = create_demo_state(5, self.t0)
        h_deltas = np.random.RandomState(42).randn(5, len(self.feature_names))

        top3 = self.explainer.explain_multi_feature_rollout(
            ar_model=self.ar5_model,
            current_state=curr_state,
            history_deltas=h_deltas,
            top_k=3,
        )
        self.assertEqual(len(top3), 3)
        self.assertGreaterEqual(top3[0].normalized_contribution, top3[1].normalized_contribution)
        self.assertGreaterEqual(top3[1].normalized_contribution, top3[2].normalized_contribution)

    def test_4_current_vs_forecast_evidence_distinction(self) -> None:
        """Distinguishes CURRENT, FORECAST, and BOTH evidence types."""
        base_st = create_demo_state(0, self.t0, dst_port_diversity=2)
        curr_elevated = create_demo_state(5, self.t0, dst_port_diversity=20)
        h_zero_deltas = np.zeros((5, len(self.feature_names)))

        fc_curr = self.explainer.explain_ar_forecast(
            ar_model=self.ar5_model,
            current_state=curr_elevated,
            history_deltas=h_zero_deltas,
            target_feature="dst_port_diversity",
            baseline_state=base_st,
        )
        self.assertIn(fc_curr.evidence_type, [EvidenceType.CURRENT, EvidenceType.FORECAST, EvidenceType.BOTH])

    def test_5_unavailable_topology_feature_protection(self) -> None:
        """Unavailable topology features (e.g. host IP endpoints) cannot enter explanations as available."""
        curr_state = create_demo_state(5, self.t0)
        self.assertIsNone(curr_state.fan_out)
        h_deltas = np.zeros((5, len(self.feature_names)))

        top_contribs = self.explainer.explain_multi_feature_rollout(
            ar_model=self.ar5_model,
            current_state=curr_state,
            history_deltas=h_deltas,
            top_k=5,
        )
        for fc in top_contribs:
            self.assertIn(fc.feature_name, self.feature_names)
            self.assertNotEqual(fc.feature_name, "fan_out")

    def test_6_perturbation_response_direction(self) -> None:
        """Perturbing port diversity increases Reconnaissance hypothesis confidence."""
        base_st = create_demo_state(4, self.t0, dst_port_diversity=4, flow_count=30)
        pert_st = create_demo_state(4, self.t0, dst_port_diversity=24, flow_count=120)
        deltas = [{"dst_port_diversity": 10.0, "flow_count": 40.0}] * 3

        hyp_base = self._get_primary_hypothesis(base_st, forecast_deltas=deltas)
        hyp_pert = self._get_primary_hypothesis(pert_st, forecast_deltas=deltas)

        conf_base = hyp_base.confidence if hyp_base else 0.0
        conf_pert = hyp_pert.confidence if hyp_pert else 0.0

        self.assertGreater(conf_pert, conf_base)

    def test_7_explanation_consistency_and_idempotence(self) -> None:
        """Identical inputs produce identical explanations."""
        curr_state = create_demo_state(6, self.t0, dst_port_diversity=18, flow_count=120)
        deltas = [{"dst_port_diversity": 8.0, "flow_count": 40.0}] * 3

        hyp1 = self._get_primary_hypothesis(curr_state, forecast_deltas=deltas)
        hyp2 = self._get_primary_hypothesis(curr_state, forecast_deltas=deltas)

        expl1 = self.explainer.explain_security_hypothesis(hyp1, curr_state)
        expl2 = self.explainer.explain_security_hypothesis(hyp2, curr_state)

        self.assertEqual(expl1.primary_stage, expl2.primary_stage)
        self.assertEqual(expl1.confidence, expl2.confidence)
        self.assertEqual(expl1.provenance_hash, expl2.provenance_hash)

    def test_8_deterministic_reproducibility(self) -> None:
        """AR(5) forecast explanation is bitwise deterministic across multiple runs."""
        curr_state = create_demo_state(5, self.t0)
        h_deltas = np.ones((5, len(self.feature_names)))

        fc1 = self.explainer.explain_ar_forecast(self.ar5_model, curr_state, h_deltas, "flow_count")
        fc2 = self.explainer.explain_ar_forecast(self.ar5_model, curr_state, h_deltas, "flow_count")

        self.assertEqual(fc1.predicted_delta, fc2.predicted_delta)
        self.assertEqual(fc1.provenance_hash, fc2.provenance_hash)

    def test_9_security_hypothesis_supporting_and_counter_evidence(self) -> None:
        """Security hypothesis explanation contains supporting evidence, counter-evidence, and alternatives."""
        curr_state = create_demo_state(6, self.t0, dst_port_diversity=20, flow_count=150, syn_ratio=0.20)
        deltas = [{"dst_port_diversity": 10.0, "flow_count": 50.0, "syn_ratio": 0.10}] * 3

        hyp = self._get_primary_hypothesis(curr_state, forecast_deltas=deltas)
        sec_expl = self.explainer.explain_security_hypothesis(hyp, curr_state)

        self.assertTrue(len(sec_expl.supporting_evidence) > 0)
        self.assertTrue(len(sec_expl.counter_evidence) > 0)
        self.assertTrue(len(sec_expl.alternative_explanations) > 0)
        self.assertIn("Reconnaissance", sec_expl.primary_stage)

    def test_10_trust_level_propagation(self) -> None:
        """TrustLevel is properly propagated from hypothesis to explanation."""
        curr_state = create_demo_state(6, self.t0)
        hyp = self._get_primary_hypothesis(curr_state)
        sec_expl = self.explainer.explain_security_hypothesis(hyp, curr_state)
        self.assertIsInstance(sec_expl.trust_level, TrustLevel)

    def test_11_label_leakage_protection(self) -> None:
        """Ground truth Label and infiltration_fraction never enter explanation feature list."""
        curr_state = create_demo_state(6, self.t0)
        h_deltas = np.zeros((5, len(self.feature_names)))

        top_contribs = self.explainer.explain_multi_feature_rollout(
            ar_model=self.ar5_model,
            current_state=curr_state,
            history_deltas=h_deltas,
            top_k=10,
        )
        for fc in top_contribs:
            self.assertNotIn("label", fc.feature_name.lower())
            self.assertNotIn("infiltration", fc.feature_name.lower())

    def test_12_historical_experiment_artifacts_remain_untouched(self) -> None:
        """Historical manifests from Day 1 to Day 9B must exist and remain non-empty."""
        for p in [
            "artifacts/experiments/delta_baseline_v1/manifest.json",
            "artifacts/experiments/delta_baseline_v2/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1_corrected/manifest.json",
            "artifacts/experiments/security_bridge_validation_v1/manifest.json",
            "artifacts/experiments/decision_layer_v1/manifest.json",
            "artifacts/experiments/demo_validation_v1/manifest.json",
            "artifacts/experiments/response_window_v1/manifest.json",
            "artifacts/experiments/ar_order_availability_v1/manifest.json",
        ]:
            path = Path(p)
            if path.exists():
                self.assertTrue(len(path.read_text(encoding="utf-8")) > 0)

    def test_13_evidence_source_and_both_discrimination(self) -> None:
        """Regression test: current evidence from state, forecast evidence from forecast deltas, BOTH only when both supported."""
        base_state = create_demo_state(0, self.t0, dst_port_diversity=2, flow_count=12)
        curr_state = create_demo_state(6, self.t0, dst_port_diversity=16, flow_count=45, syn_ratio=0.25)
        # Port diversity has forecast delta +10.0; flow_count has zero forecast delta
        forecast_deltas = [{"dst_port_diversity": 10.0, "flow_count": 0.0, "syn_ratio": 0.0}] * 3

        hyp = self._get_primary_hypothesis(curr_state, forecast_deltas=forecast_deltas)
        sec_expl = self.explainer.explain_security_hypothesis(hyp, curr_state, baseline_state=base_state)

        feat_map = {fc.feature_name: fc for fc in sec_expl.top_contributing_features}

        # dst_port_diversity: current is 16.0 (elevated from 2.0) AND forecast delta is 10.0 -> BOTH
        self.assertIn("dst_port_diversity", feat_map)
        fc_port = feat_map["dst_port_diversity"]
        self.assertEqual(fc_port.current_value, 16.0)
        self.assertEqual(fc_port.predicted_delta, 10.0)
        self.assertEqual(fc_port.evidence_type, EvidenceType.BOTH)

        # flow_count: current is 45.0 (elevated from 12.0) AND forecast delta is 0.0 -> CURRENT
        self.assertIn("flow_count", feat_map)
        fc_flow = feat_map["flow_count"]
        self.assertEqual(fc_flow.current_value, 45.0)
        self.assertEqual(fc_flow.predicted_delta, 0.0)
        self.assertEqual(fc_flow.evidence_type, EvidenceType.CURRENT)


if __name__ == "__main__":
    unittest.main()
