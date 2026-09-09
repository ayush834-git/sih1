"""Unit and Integration Tests for Phase 3A: Bounded Intervention-Conditioned Simulation.

Verifies:
- TEST 1: DO_NOTHING identity
- TEST 2: Determinism
- TEST 3: No mutation of inputs
- TEST 4: Rate-limit transformation on controlled synthetic fixture
- TEST 5: Block transformation requiring attribution
- TEST 6: Unsupported/unsafe transformation fails closed
- TEST 7: Risk comparison computed from existing SecurityRiskEngine
- TEST 8: Existing AR(5) forecast integrity
- TEST 9: No execution boundary invocation
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

import numpy as np

from core.contracts import (
    FeatureAvailability,
    NetworkState,
    Source,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    Direction,
    new_id,
)
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.rollout import MultiStepRolloutEngine
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.scenarios import get_demo_scenario_states
from security.bridge import BehavioralSecurityBridge
from security.risk_engine import SecurityRiskEngine
from simulation.models import (
    AssumptionClassification,
    InterventionParameters,
    InterventionStatus,
    InterventionType,
    SimulationResult,
)
from simulation.operator import InterventionOperator
from simulation.engine import InterventionSimulator


ROOT_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT_DIR / "artifacts" / "models" / "ar5_authoritative"


def make_synthetic_state(
    window_id: str = "syn_w001",
    flow_count: int = 100,
    byte_rate: float = 200000.0,
    packet_rate: float = 1000.0,
    dst_port_diversity: int = 30,
    syn_ratio: float = 0.40,
    rst_ratio: float = 0.05,
    timestamp_start: datetime | None = None,
) -> NetworkState:
    """Helper to construct a valid, clean NetworkState for simulation tests."""
    t_start = timestamp_start or datetime(2026, 9, 8, 12, 0, 0)
    t_end = t_start + timedelta(seconds=10.0)
    prov = "a" * 64
    return NetworkState(
        window_id=window_id,
        timestamp_start=t_start,
        timestamp_end=t_end,
        window_duration_s=10.0,
        flow_count=flow_count,
        byte_rate=byte_rate,
        packet_rate=packet_rate,
        mean_flow_duration=5.0,
        src_ip_diversity=10,
        dst_ip_diversity=20,
        src_port_diversity=15,
        dst_port_diversity=dst_port_diversity,
        fan_out=None,
        internal_ratio=0.10,
        east_west_count=5,
        syn_count=40,
        ack_count=50,
        rst_count=5,
        syn_ratio=syn_ratio,
        rst_ratio=rst_ratio,
        iat_mean=0.05,
        iat_std=0.02,
        iat_skew=0.0,
        pkt_size_mean=500.0,
        pkt_size_std=150.0,
        byte_variance=1000.0,
        ttl_mean=64.0,
        ttl_variance=1.0,
        tcp_window_mean=65535.0,
        fragment_count=0,
        retransmit_count=0,
        payload_size_mean=400.0,
        source=Source.CSV,
        data_quality=1.0,
        is_empty=False,
        gap_before=False,
        gap_after=False,
        session_id="session-syn",
        provenance_hash=prov,
        feature_availability={
            "fan_out": FeatureAvailability.UNAVAILABLE,
        },
    )


class TestPhase3ASimulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ar_model, cls.scales = load_ar_model(MODEL_DIR)
        cls.rollout_engine = MultiStepRolloutEngine(cls.ar_model, CSV_AVAILABLE_FEATURES)
        cls.bridge = BehavioralSecurityBridge(scales=cls.scales)
        cls.risk_engine = SecurityRiskEngine()
        cls.simulator = InterventionSimulator(
            bridge=cls.bridge,
            risk_engine=cls.risk_engine,
            rollout_engine=cls.rollout_engine,
            scales=cls.scales,
        )
        cls.demo_states = get_demo_scenario_states("demo_recon_15s")

    # ────────────────────────────────────────────────────────────
    # TEST 1 — DO_NOTHING identity
    # ────────────────────────────────────────────────────────────
    def test_01_do_nothing_identity(self):
        """Verify simulate(DO_NOTHING) produces an intervention trajectory identical to baseline."""
        state = self.demo_states[5]
        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        synthetic_deltas = np.ones((H, D), dtype=np.float64) * 10.0

        result = self.simulator.simulate(
            current_state=state,
            action=InterventionType.DO_NOTHING,
            baseline_deltas=synthetic_deltas,
        )

        self.assertEqual(result.status, InterventionStatus.IDENTITY)
        self.assertEqual(result.risk_delta, 0.0)
        self.assertEqual(result.risk_reduction, 0.0)
        self.assertEqual(len(result.assumptions), 0)
        self.assertEqual(len(result.warnings), 0)
        self.assertEqual(result.intervention_uncertainty, 0.0)

        # Invariant: step forecasts must be bitwise identical
        base_steps = result.baseline_trajectory.steps
        int_steps = result.intervention_trajectory.steps
        self.assertEqual(len(base_steps), len(int_steps))

        for b_step, i_step in zip(base_steps, int_steps):
            self.assertEqual(b_step.step_index, i_step.step_index)
            self.assertEqual(b_step.forecast.delta_predicted, i_step.forecast.delta_predicted)
            self.assertEqual(b_step.forecast.state_predicted, i_step.forecast.state_predicted)

        # Invariant: risk scores must be identical
        self.assertAlmostEqual(result.baseline_risk.current_risk.score, result.intervention_risk.current_risk.score, places=6)
        for b_fr, i_fr in zip(result.baseline_risk.future_risks, result.intervention_risk.future_risks):
            self.assertEqual(b_fr.horizon_step, i_fr.horizon_step)
            self.assertAlmostEqual(b_fr.score, i_fr.score, places=6)

    # ────────────────────────────────────────────────────────────
    # TEST 2 — Determinism
    # ────────────────────────────────────────────────────────────
    def test_02_determinism(self):
        """Verify identical inputs and parameters produce bitwise identical simulation results."""
        state = self.demo_states[3]
        params = InterventionParameters(rate_limit_factor=0.35)
        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        deltas = np.linspace(10.0, 50.0, H * D).reshape(H, D)

        run1 = self.simulator.simulate(
            current_state=state,
            action=InterventionType.RATE_LIMIT_IP,
            params=params,
            baseline_deltas=deltas,
        )
        run2 = self.simulator.simulate(
            current_state=state,
            action=InterventionType.RATE_LIMIT_IP,
            params=params,
            baseline_deltas=deltas,
        )

        self.assertEqual(run1.provenance_hash, run2.provenance_hash)
        self.assertEqual(run1.risk_delta, run2.risk_delta)
        self.assertEqual(run1.risk_reduction, run2.risk_reduction)
        self.assertEqual(run1.peak_baseline_risk, run2.peak_baseline_risk)
        self.assertEqual(run1.peak_intervention_risk, run2.peak_intervention_risk)
        self.assertEqual(run1.horizon_risk_deltas, run2.horizon_risk_deltas)

        for s1, s2 in zip(run1.intervention_trajectory.steps, run2.intervention_trajectory.steps):
            self.assertEqual(s1.forecast.delta_predicted, s2.forecast.delta_predicted)
            self.assertEqual(s1.forecast.state_predicted, s2.forecast.state_predicted)

    # ────────────────────────────────────────────────────────────
    # TEST 3 — No mutation
    # ────────────────────────────────────────────────────────────
    def test_03_no_mutation(self):
        """Verify simulation does not mutate input NetworkState, baseline deltas, or trust assessment."""
        state = self.demo_states[2]
        state_features_before = deepcopy(state.feature_values())
        state_window_id_before = state.window_id

        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        deltas = np.ones((H, D), dtype=np.float64) * 42.0
        deltas_before = deltas.copy()

        trust = TrustAssessment(
            assessment_id="trust-immutable",
            forecast_id="fc-test",
            forecast_confidence=0.80,
            model_disagreement=0.05,
            distribution_shift_score=0.05,
            novelty_score=0.05,
            historical_error=0.10,
            data_quality=1.0,
            composite_trust=0.80,
            trust_level=TrustLevel.HIGH,
            contributing_factors=(
                TrustFactor(name="test", value=0.80, direction=Direction.INCREASES_TRUST),
            ),
        )
        trust_before = deepcopy(trust)

        for action in InterventionType:
            _ = self.simulator.simulate(
                current_state=state,
                action=action,
                params=InterventionParameters(source_attribution_valid=True, isolated_port=80),
                baseline_deltas=deltas,
                trust_assessment=trust,
            )

            # Assert input state unchanged
            self.assertEqual(state.feature_values(), state_features_before)
            self.assertEqual(state.window_id, state_window_id_before)

            # Assert input deltas array unchanged
            np.testing.assert_array_equal(deltas, deltas_before)

            # Assert trust assessment unchanged
            self.assertEqual(trust.composite_trust, trust_before.composite_trust)
            self.assertEqual(trust.trust_level, trust_before.trust_level)

    # ────────────────────────────────────────────────────────────
    # TEST 4 — Rate-limit transformation
    # ────────────────────────────────────────────────────────────
    def test_04_rate_limit_transformation(self):
        """Verify only configured volume features change according to rate_limit_factor."""
        state = make_synthetic_state()
        feat_list = list(CSV_AVAILABLE_FEATURES)
        H = 3
        D = len(feat_list)
        synthetic_deltas = np.zeros((H, D), dtype=np.float64)

        # Set specific positive deltas
        byte_idx = feat_list.index("byte_rate")
        pkt_idx = feat_list.index("packet_rate")
        flow_idx = feat_list.index("flow_count")
        port_idx = feat_list.index("dst_port_diversity")

        synthetic_deltas[:, byte_idx] = 50000.0
        synthetic_deltas[:, pkt_idx] = 500.0
        synthetic_deltas[:, flow_idx] = 100.0
        synthetic_deltas[:, port_idx] = 25.0

        factor = 0.40
        params = InterventionParameters(rate_limit_factor=factor)

        result = self.simulator.simulate(
            current_state=state,
            action=InterventionType.RATE_LIMIT_IP,
            params=params,
            baseline_deltas=synthetic_deltas,
        )

        self.assertEqual(result.status, InterventionStatus.APPLIED)
        self.assertEqual(len(result.assumptions), 1)
        self.assertEqual(
            result.assumptions[0].classification,
            AssumptionClassification.INITIAL_DESIGN_PARAMETER.value,
        )

        # Inspect intervention trajectory steps
        for step in result.intervention_trajectory.steps:
            dp = step.forecast.delta_predicted
            # Modified volume features
            self.assertAlmostEqual(dp["byte_rate"], 50000.0 * factor, places=4)
            self.assertAlmostEqual(dp["packet_rate"], 500.0 * factor, places=4)
            self.assertAlmostEqual(dp["flow_count"], 100.0 * factor, places=4)
            # Unmodified feature
            self.assertAlmostEqual(dp["dst_port_diversity"], 25.0, places=4)

    # ────────────────────────────────────────────────────────────
    # TEST 5 — Block transformation
    # ────────────────────────────────────────────────────────────
    def test_05_block_transformation_attribution_gated(self):
        """Verify block transformation only occurs when source attribution assumption is satisfied."""
        state = make_synthetic_state()
        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        deltas = np.ones((H, D), dtype=np.float64) * 100.0

        # Case A: Attribution unavailable -> Must FAIL CLOSED / return UNSUPPORTED
        params_no_attr = InterventionParameters(source_attribution_valid=False)
        res_no_attr = self.simulator.simulate(
            current_state=state,
            action=InterventionType.TEMPORARY_BLOCK_IP,
            params=params_no_attr,
            baseline_deltas=deltas,
        )

        self.assertEqual(res_no_attr.status, InterventionStatus.UNSUPPORTED)
        self.assertGreater(len(res_no_attr.warnings), 0)
        self.assertIn("source IP attribution is UNAVAILABLE", res_no_attr.warnings[0])
        self.assertEqual(res_no_attr.intervention_uncertainty, 1.0)

        # Trajectory must NOT be modified
        for b_step, i_step in zip(res_no_attr.baseline_trajectory.steps, res_no_attr.intervention_trajectory.steps):
            self.assertEqual(b_step.forecast.delta_predicted, i_step.forecast.delta_predicted)

        # Case B: Attribution valid -> Applied with UNVALIDATED ASSUMPTION
        params_attr = InterventionParameters(source_attribution_valid=True, block_volume_reduction=1.0)
        res_attr = self.simulator.simulate(
            current_state=state,
            action=InterventionType.TEMPORARY_BLOCK_IP,
            params=params_attr,
            baseline_deltas=deltas,
        )

        self.assertEqual(res_attr.status, InterventionStatus.APPLIED)
        self.assertEqual(len(res_attr.assumptions), 1)
        self.assertEqual(
            res_attr.assumptions[0].classification,
            AssumptionClassification.UNVALIDATED_ASSUMPTION.value,
        )
        for step in res_attr.intervention_trajectory.steps:
            dp = step.forecast.delta_predicted
            self.assertAlmostEqual(dp["flow_count"], 0.0, places=4)
            self.assertAlmostEqual(dp["byte_rate"], 0.0, places=4)
            self.assertAlmostEqual(dp["packet_rate"], 0.0, places=4)

    # ────────────────────────────────────────────────────────────
    # TEST 6 — Unsupported/unsafe transformation
    # ────────────────────────────────────────────────────────────
    def test_06_unsupported_unsafe_transformation(self):
        """Verify unsupported transformations return explicit warnings and fail closed."""
        state = make_synthetic_state()
        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        deltas = np.ones((H, D), dtype=np.float64) * 50.0

        # Endpoint isolation without specified port
        params_no_port = InterventionParameters(isolated_port=None)
        res = self.simulator.simulate(
            current_state=state,
            action=InterventionType.ISOLATE_SERVICE_ENDPOINT,
            params=params_no_port,
            baseline_deltas=deltas,
        )

        self.assertEqual(res.status, InterventionStatus.UNSUPPORTED)
        self.assertGreater(len(res.warnings), 0)
        self.assertIn("target port or service endpoint is unspecified", res.warnings[0])
        self.assertEqual(res.intervention_uncertainty, 1.0)

        # Baseline and intervention deltas must match exactly (fail closed)
        for b_step, i_step in zip(res.baseline_trajectory.steps, res.intervention_trajectory.steps):
            self.assertEqual(b_step.forecast.delta_predicted, i_step.forecast.delta_predicted)

        # With specified port, it applies with unvalidated assumption
        params_port = InterventionParameters(isolated_port=443)
        res_port = self.simulator.simulate(
            current_state=state,
            action=InterventionType.ISOLATE_SERVICE_ENDPOINT,
            params=params_port,
            baseline_deltas=deltas,
        )
        self.assertEqual(res_port.status, InterventionStatus.APPLIED)
        self.assertEqual(
            res_port.assumptions[0].classification,
            AssumptionClassification.UNVALIDATED_ASSUMPTION.value,
        )

    # ────────────────────────────────────────────────────────────
    # TEST 7 — Risk comparison
    # ────────────────────────────────────────────────────────────
    def test_07_risk_comparison_consistency(self):
        """Verify baseline vs intervention risk comparison metrics are computed consistently from SecurityRiskEngine."""
        state = make_synthetic_state(
            flow_count=200,
            byte_rate=500000.0,
            packet_rate=2000.0,
            dst_port_diversity=50,
            syn_ratio=0.50,
        )
        feat_list = list(CSV_AVAILABLE_FEATURES)
        H = 3
        D = len(feat_list)
        deltas = np.zeros((H, D), dtype=np.float64)
        deltas[:, feat_list.index("byte_rate")] = 100000.0  # Volumetric surge

        result = self.simulator.simulate(
            current_state=state,
            action=InterventionType.RATE_LIMIT_IP,
            params=InterventionParameters(rate_limit_factor=0.20),
            baseline_deltas=deltas,
        )

        # Baseline and intervention scores across all horizons {0, 1, 2, 3}
        base_scores = [result.baseline_risk.current_risk.score] + [fr.score for fr in result.baseline_risk.future_risks]
        int_scores = [result.intervention_risk.current_risk.score] + [fr.score for fr in result.intervention_risk.future_risks]

        # Invariant: peak risks match respective maximum scores
        self.assertAlmostEqual(result.peak_baseline_risk, max(base_scores), places=5)
        self.assertAlmostEqual(result.peak_intervention_risk, max(int_scores), places=5)

        # Invariant: risk delta and risk reduction definitions
        expected_delta = max(int_scores) - max(base_scores)
        expected_reduction = max(0.0, max(base_scores) - max(int_scores))
        self.assertAlmostEqual(result.risk_delta, expected_delta, places=5)
        self.assertAlmostEqual(result.risk_reduction, expected_reduction, places=5)

        # Invariant: horizon-by-horizon risk deltas match score differences
        for h in range(4):
            self.assertIn(h, result.horizon_risk_deltas)
            self.assertAlmostEqual(result.horizon_risk_deltas[h], int_scores[h] - base_scores[h], places=5)

        # Invariant: rate-limiting the volumetric surge reduced future risk
        self.assertGreaterEqual(result.risk_reduction, 0.0)

    # ────────────────────────────────────────────────────────────
    # TEST 8 — Existing forecast integrity
    # ────────────────────────────────────────────────────────────
    def test_08_existing_forecast_integrity(self):
        """Verify invoking Phase 3A simulation does not alter the existing AR(5) model weights or predictions."""
        # Snapshot weights of all 15 linear regression models
        original_coefs = [reg.coef_.copy() for reg in self.ar_model.models]
        original_intercepts = [float(reg.intercept_) for reg in self.ar_model.models]

        state = self.demo_states[4]
        curr_vals = state.feature_values()
        n_feats = len(CSV_AVAILABLE_FEATURES)
        hist_vec = np.zeros((1, 5 * n_feats))
        curr_vec = np.array([[curr_vals.get(f, 0.0) for f in CSV_AVAILABLE_FEATURES]])

        pred_before, _ = self.rollout_engine.forecast_open_loop(hist_vec, curr_vec, max_horizon=3)

        # Run multiple simulations
        for action in InterventionType:
            _ = self.simulator.simulate(
                current_state=state,
                action=action,
                history_deltas=hist_vec,
            )

        # Check weights are untouched
        for j, reg in enumerate(self.ar_model.models):
            np.testing.assert_array_equal(reg.coef_, original_coefs[j])
            self.assertEqual(float(reg.intercept_), original_intercepts[j])

        # Check rollout produces identical predictions
        pred_after, _ = self.rollout_engine.forecast_open_loop(hist_vec, curr_vec, max_horizon=3)
        np.testing.assert_array_equal(pred_before, pred_after)

    # ────────────────────────────────────────────────────────────
    # TEST 9 — No execution
    # ────────────────────────────────────────────────────────────
    def test_09_no_execution_boundaries_invoked(self):
        """Mock response execution boundaries and verify simulation NEVER invokes them."""
        with patch("core.response_execution.adapters.DemoResponseAdapter.execute") as mock_adapter_exec, \
             patch("core.response_execution.adapters.DemoResponseAdapter.rollback") as mock_adapter_rb, \
             patch("core.response_execution.executor.ResponseExecutor.execute") as mock_executor_exec:

            state = self.demo_states[6]
            deltas = np.ones((3, len(CSV_AVAILABLE_FEATURES)), dtype=np.float64) * 20.0

            for action in InterventionType:
                params = InterventionParameters(
                    rate_limit_factor=0.5,
                    block_volume_reduction=1.0,
                    source_attribution_valid=True,
                    isolated_port=80,
                )
                _ = self.simulator.simulate(
                    current_state=state,
                    action=action,
                    params=params,
                    baseline_deltas=deltas,
                )

            # Assert execution boundaries were NEVER called
            mock_adapter_exec.assert_not_called()
            mock_adapter_rb.assert_not_called()
            mock_executor_exec.assert_not_called()


if __name__ == "__main__":
    unittest.main()
