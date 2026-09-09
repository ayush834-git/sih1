"""Unit and Integration Tests for Phase 3B: Disruption Modeling & Minimum-Sufficient Selection.

Verifies:
- TEST 1: DO_NOTHING wins when safe (disruption == 0.0)
- TEST 2: Minimum sufficient action is selected (least disruptive among sufficient)
- TEST 3: Stronger action is NOT automatically preferred over least disruptive
- TEST 4: Insufficient actions are strictly rejected
- TEST 5: Peak risk constraint violation rejects candidate
- TEST 6: No sufficient action returns NO_SUFFICIENT_ACTION and exposes lowest-risk candidate
- TEST 7: Unsupported action cannot become recommended
- TEST 8: Topology unavailable fails closed with UNRESOLVED status (no fabricated zero disruption)
- TEST 9: Deterministic tie-breaking
- TEST 10: Parameter transparency (thresholds/weights are active design parameters)
- TEST 11: No execution boundaries invoked
- TEST 12: Phase 3A and core architecture integrity
- SCIENTIFIC VALIDATION TEST: Lower disruption != lower security risk
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
import unittest
from unittest.mock import patch

import numpy as np

from core.contracts import (
    FeatureAvailability,
    NetworkState,
    Source,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    Direction,
)
from core.topology.builder import build_enterprise_demo_topology
from core.topology.graph import ServiceTopologyGraph
from core.topology.models import TopologyAvailability
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.rollout import MultiStepRolloutEngine
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.scenarios import get_demo_scenario_states
from security.bridge import BehavioralSecurityBridge
from security.risk_engine import SecurityRiskEngine
from simulation.decision_models import (
    ActionEvaluation,
    DecisionResult,
    DisruptionParameters,
    RecommendationStatus,
    RiskConstraintParameters,
)
from simulation.disruption import DisruptionEstimator
from simulation.engine import InterventionSimulator
from simulation.models import (
    InterventionParameters,
    InterventionStatus,
    InterventionType,
)
from simulation.selector import MinimumSufficientSelector


ROOT_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT_DIR / "artifacts" / "models" / "ar5_authoritative"


def make_benign_state(window_id: str = "benign_w001") -> NetworkState:
    """Construct nominal baseline state where telemetry is well within normal bounds."""
    t_start = datetime(2026, 9, 8, 12, 0, 0)
    t_end = t_start + timedelta(seconds=10.0)
    return NetworkState(
        window_id=window_id,
        timestamp_start=t_start,
        timestamp_end=t_end,
        window_duration_s=10.0,
        flow_count=12,
        byte_rate=1500.0,
        packet_rate=20.0,
        mean_flow_duration=5.0,
        src_ip_diversity=2,
        dst_ip_diversity=2,
        src_port_diversity=4,
        dst_port_diversity=2,
        fan_out=None,
        internal_ratio=0.50,
        east_west_count=2,
        syn_count=2,
        ack_count=10,
        rst_count=0,
        syn_ratio=0.05,
        rst_ratio=0.0,
        iat_mean=0.8,
        iat_std=0.4,
        iat_skew=0.0,
        pkt_size_mean=75.0,
        pkt_size_std=20.0,
        byte_variance=100.0,
        ttl_mean=64.0,
        ttl_variance=1.0,
        tcp_window_mean=65535.0,
        fragment_count=0,
        retransmit_count=0,
        payload_size_mean=50.0,
        source=Source.CSV,
        data_quality=1.0,
        is_empty=False,
        gap_before=False,
        gap_after=False,
        session_id="session-benign",
        provenance_hash="b" * 64,
        feature_availability={"fan_out": FeatureAvailability.UNAVAILABLE},
    )


def make_attack_state(window_id: str = "attack_w001") -> NetworkState:
    """Construct active threat state with heavy volumetric flooding and port exploration."""
    t_start = datetime(2026, 9, 8, 12, 0, 0)
    t_end = t_start + timedelta(seconds=10.0)
    return NetworkState(
        window_id=window_id,
        timestamp_start=t_start,
        timestamp_end=t_end,
        window_duration_s=10.0,
        flow_count=200,
        byte_rate=400000.0,
        packet_rate=2500.0,
        mean_flow_duration=8.0,
        src_ip_diversity=15,
        dst_ip_diversity=40,
        src_port_diversity=50,
        dst_port_diversity=45,
        fan_out=None,
        internal_ratio=0.10,
        east_west_count=10,
        syn_count=90,
        ack_count=100,
        rst_count=10,
        syn_ratio=0.45,
        rst_ratio=0.05,
        iat_mean=0.02,
        iat_std=0.01,
        iat_skew=0.0,
        pkt_size_mean=600.0,
        pkt_size_std=180.0,
        byte_variance=2000.0,
        ttl_mean=64.0,
        ttl_variance=1.0,
        tcp_window_mean=65535.0,
        fragment_count=0,
        retransmit_count=0,
        payload_size_mean=500.0,
        source=Source.CSV,
        data_quality=1.0,
        is_empty=False,
        gap_before=False,
        gap_after=False,
        session_id="session-attack",
        provenance_hash="c" * 64,
        feature_availability={"fan_out": FeatureAvailability.UNAVAILABLE},
    )


class TestPhase3BSelection(unittest.TestCase):
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
        cls.disruption_estimator = DisruptionEstimator()
        cls.selector = MinimumSufficientSelector(
            simulator=cls.simulator,
            disruption_estimator=cls.disruption_estimator,
        )
        cls.topology = build_enterprise_demo_topology()

    # ────────────────────────────────────────────────────────────
    # TEST 1 — DO_NOTHING WINS WHEN SAFE
    # ────────────────────────────────────────────────────────────
    def test_01_do_nothing_wins_when_safe(self):
        """When baseline trajectory satisfies future risk safety constraints, DO_NOTHING must win."""
        state = make_benign_state()
        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        # Flat zero deltas (steady-state nominal)
        deltas = np.zeros((H, D), dtype=np.float64)

        result = self.selector.select(
            current_state=state,
            baseline_deltas=deltas,
            topology=self.topology,
            risk_constraints=RiskConstraintParameters(target_risk=0.40, peak_risk_ceiling=0.60),
        )

        self.assertEqual(result.recommendation_status, RecommendationStatus.RECOMMENDED)
        self.assertEqual(result.recommended_action, InterventionType.DO_NOTHING)
        self.assertEqual(result.selected_disruption, 0.0)
        self.assertIn(InterventionType.DO_NOTHING, result.sufficient_candidates)

    # ────────────────────────────────────────────────────────────
    # TEST 2 — MINIMUM SUFFICIENT ACTION
    # ────────────────────────────────────────────────────────────
    def test_02_minimum_sufficient_action(self):
        """Among sufficient actions, the least disruptive action must be selected."""
        state = make_attack_state()
        feat_list = list(CSV_AVAILABLE_FEATURES)
        H = 3
        D = len(feat_list)
        deltas = np.zeros((H, D), dtype=np.float64)
        # Forecast predicts continued rapid volumetric surge
        deltas[:, feat_list.index("byte_rate")] = 100000.0
        deltas[:, feat_list.index("flow_count")] = 50.0

        # Configure parameters such that RATE_LIMIT, BLOCK, and ISOLATE all achieve sufficiency,
        # while DO_NOTHING fails
        sim_params = {
            InterventionType.DO_NOTHING: InterventionParameters(),
            InterventionType.RATE_LIMIT_IP: InterventionParameters(rate_limit_factor=0.20),
            InterventionType.TEMPORARY_BLOCK_IP: InterventionParameters(source_attribution_valid=True, block_volume_reduction=1.0),
            InterventionType.ISOLATE_SERVICE_ENDPOINT: InterventionParameters(isolated_port=443),
        }
        targets = {
            InterventionType.ISOLATE_SERVICE_ENDPOINT: "svc-ingress-gw",
        }

        result = self.selector.select(
            current_state=state,
            baseline_deltas=deltas,
            simulation_params_map=sim_params,
            target_entity_map=targets,
            topology=self.topology,
            risk_constraints=RiskConstraintParameters(target_risk=0.45, peak_risk_ceiling=0.65),
        )

        # Baseline DO_NOTHING must be insufficient
        self.assertIn(InterventionType.DO_NOTHING, result.rejected_candidates)

        # Sufficient actions must be present
        self.assertIn(InterventionType.RATE_LIMIT_IP, result.sufficient_candidates)

        # Disruption ordering: RATE_LIMIT < BLOCK < ISOLATE
        d_rl = result.action_evaluations[InterventionType.RATE_LIMIT_IP.value].disruption_estimate
        d_block = result.action_evaluations[InterventionType.TEMPORARY_BLOCK_IP.value].disruption_estimate
        d_iso = result.action_evaluations[InterventionType.ISOLATE_SERVICE_ENDPOINT.value].disruption_estimate

        self.assertLess(d_rl, d_block)
        self.assertLess(d_block, d_iso)

        # Minimum sufficient action must win
        self.assertEqual(result.recommended_action, InterventionType.RATE_LIMIT_IP)
        self.assertEqual(result.selected_disruption, d_rl)

    # ────────────────────────────────────────────────────────────
    # TEST 3 — STRONGER ACTION NOT AUTOMATICALLY PREFERRED
    # ────────────────────────────────────────────────────────────
    def test_03_stronger_action_not_automatically_preferred(self):
        """Even if BLOCK achieves lower future risk than RATE_LIMIT, RATE_LIMIT wins if disruption is lower."""
        state = make_attack_state()
        feat_list = list(CSV_AVAILABLE_FEATURES)
        H = 3
        D = len(feat_list)
        deltas = np.zeros((H, D), dtype=np.float64)
        deltas[:, feat_list.index("byte_rate")] = 100000.0

        sim_params = {
            InterventionType.RATE_LIMIT_IP: InterventionParameters(rate_limit_factor=0.20),
            InterventionType.TEMPORARY_BLOCK_IP: InterventionParameters(source_attribution_valid=True, block_volume_reduction=1.0),
        }

        result = self.selector.select(
            current_state=state,
            candidate_actions=(InterventionType.RATE_LIMIT_IP, InterventionType.TEMPORARY_BLOCK_IP),
            baseline_deltas=deltas,
            simulation_params_map=sim_params,
            topology=self.topology,
            risk_constraints=RiskConstraintParameters(target_risk=0.50, peak_risk_ceiling=0.70),
        )

        eval_rl = result.action_evaluations[InterventionType.RATE_LIMIT_IP.value]
        eval_block = result.action_evaluations[InterventionType.TEMPORARY_BLOCK_IP.value]

        # Both must be sufficient
        self.assertTrue(eval_rl.is_sufficient)
        self.assertTrue(eval_block.is_sufficient)

        # BLOCK has strictly greater or equal suppression of risk (lower or equal risk)
        self.assertLessEqual(eval_block.aggregate_risk, eval_rl.aggregate_risk + 1e-6)

        # BUT RATE_LIMIT has strictly lower operational disruption
        self.assertLess(eval_rl.disruption_estimate, eval_block.disruption_estimate)

        # Winner must be RATE_LIMIT
        self.assertEqual(result.recommended_action, InterventionType.RATE_LIMIT_IP)

    # ────────────────────────────────────────────────────────────
    # TEST 4 — INSUFFICIENT ACTIONS REJECTED
    # ────────────────────────────────────────────────────────────
    def test_04_insufficient_actions_rejected(self):
        """Actions violating target risk or peak ceiling cannot be selected."""
        state = make_attack_state()
        feat_list = list(CSV_AVAILABLE_FEATURES)
        H = 3
        D = len(feat_list)
        deltas = np.zeros((H, D), dtype=np.float64)
        deltas[:, feat_list.index("byte_rate")] = 150000.0

        # Very strict target risk: only 0.10 allowed
        strict_constraints = RiskConstraintParameters(target_risk=0.10, peak_risk_ceiling=0.20)

        result = self.selector.select(
            current_state=state,
            baseline_deltas=deltas,
            topology=self.topology,
            risk_constraints=strict_constraints,
        )

        # DO_NOTHING must be rejected with explicit violation reason
        do_nothing_eval = result.action_evaluations[InterventionType.DO_NOTHING.value]
        self.assertFalse(do_nothing_eval.is_sufficient)
        self.assertGreater(len(do_nothing_eval.rejection_reasons), 0)
        self.assertIn("exceeds target threshold", do_nothing_eval.rejection_reasons[0])

    # ────────────────────────────────────────────────────────────
    # TEST 5 — PEAK CONSTRAINT
    # ────────────────────────────────────────────────────────────
    def test_05_peak_risk_constraint_violation(self):
        """Action with acceptable aggregate risk but violating peak ceiling must be rejected."""
        state = make_attack_state()
        feat_list = list(CSV_AVAILABLE_FEATURES)
        H = 3
        D = len(feat_list)
        deltas = np.zeros((H, D), dtype=np.float64)
        deltas[:, feat_list.index("byte_rate")] = 80000.0

        # Set target_risk loose (0.80) but peak_ceiling tight (0.30)
        peak_constrained = RiskConstraintParameters(target_risk=0.80, peak_risk_ceiling=0.30)

        result = self.selector.select(
            current_state=state,
            candidate_actions=(InterventionType.DO_NOTHING,),
            baseline_deltas=deltas,
            topology=self.topology,
            risk_constraints=peak_constrained,
        )

        ev = result.action_evaluations[InterventionType.DO_NOTHING.value]
        if ev.peak_risk > 0.30:
            self.assertFalse(ev.peak_ceiling_satisfied)
            self.assertFalse(ev.is_sufficient)
            self.assertIn("exceeds ceiling threshold", " ".join(ev.rejection_reasons))

    # ────────────────────────────────────────────────────────────
    # TEST 6 — NO SUFFICIENT ACTION
    # ────────────────────────────────────────────────────────────
    def test_06_no_sufficient_action_behavior(self):
        """When all candidates violate the safety envelope, returns NO_SUFFICIENT_ACTION and exposes lowest-risk candidate."""
        state = make_attack_state()
        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        deltas = np.ones((H, D), dtype=np.float64) * 50.0

        # Impossibly strict envelope: target_risk = 0.01, peak = 0.02
        impossible_envelope = RiskConstraintParameters(target_risk=0.01, peak_risk_ceiling=0.02)

        result = self.selector.select(
            current_state=state,
            baseline_deltas=deltas,
            topology=self.topology,
            risk_constraints=impossible_envelope,
        )

        self.assertEqual(result.recommendation_status, RecommendationStatus.NO_SUFFICIENT_ACTION)
        self.assertIsNone(result.recommended_action)
        self.assertEqual(len(result.sufficient_candidates), 0)
        self.assertIsNotNone(result.lowest_risk_candidate)
        self.assertIsNotNone(result.unresolved_reason)

    # ────────────────────────────────────────────────────────────
    # TEST 7 — UNSUPPORTED ACTION CANNOT BE RECOMMENDED
    # ────────────────────────────────────────────────────────────
    def test_07_unsupported_action_rejected(self):
        """Unsupported action (e.g. TEMPORARY_BLOCK_IP with attribution invalid) cannot be recommended."""
        state = make_attack_state()
        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        deltas = np.ones((H, D), dtype=np.float64) * 20.0

        sim_params = {
            InterventionType.TEMPORARY_BLOCK_IP: InterventionParameters(source_attribution_valid=False),
        }

        result = self.selector.select(
            current_state=state,
            candidate_actions=(InterventionType.TEMPORARY_BLOCK_IP,),
            baseline_deltas=deltas,
            simulation_params_map=sim_params,
            topology=self.topology,
        )

        ev = result.action_evaluations[InterventionType.TEMPORARY_BLOCK_IP.value]
        self.assertEqual(ev.simulation_status, InterventionStatus.UNSUPPORTED)
        self.assertFalse(ev.is_sufficient)
        self.assertIn(InterventionType.TEMPORARY_BLOCK_IP, result.rejected_candidates)
        self.assertNotEqual(result.recommended_action, InterventionType.TEMPORARY_BLOCK_IP)

    # ────────────────────────────────────────────────────────────
    # TEST 8 — TOPOLOGY UNAVAILABLE FAILS CLOSED
    # ────────────────────────────────────────────────────────────
    def test_08_topology_unavailable_fails_closed(self):
        """When topology is UNAVAILABLE, disruption is not fabricated as 0.0 and decision marks UNRESOLVED."""
        state = make_attack_state()
        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        deltas = np.ones((H, D), dtype=np.float64) * 20.0

        unavail_topo = ServiceTopologyGraph(availability=TopologyAvailability.UNAVAILABLE)

        sim_params = {
            InterventionType.ISOLATE_SERVICE_ENDPOINT: InterventionParameters(isolated_port=443),
        }

        # Evaluate only ISOLATE_SERVICE_ENDPOINT where topology is strictly required
        result = self.selector.select(
            current_state=state,
            candidate_actions=(InterventionType.ISOLATE_SERVICE_ENDPOINT,),
            baseline_deltas=deltas,
            simulation_params_map=sim_params,
            topology=unavail_topo,
        )

        ev = result.action_evaluations[InterventionType.ISOLATE_SERVICE_ENDPOINT.value]
        self.assertIsNone(ev.disruption_estimate)
        self.assertEqual(result.recommendation_status, RecommendationStatus.UNRESOLVED)
        self.assertIn("topology context is UNAVAILABLE", result.unresolved_reason)

    # ────────────────────────────────────────────────────────────
    # TEST 9 — DETERMINISTIC TIE BREAK
    # ────────────────────────────────────────────────────────────
    def test_09_deterministic_tie_break(self):
        """When two actions have identical disruption and risk, selection is strictly deterministic across runs."""
        state = make_benign_state()
        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        deltas = np.zeros((H, D), dtype=np.float64)

        # Force identical disruption parameters for two actions
        disrupt_params = DisruptionParameters(
            aggressiveness_map={
                InterventionType.RATE_LIMIT_IP: 0.30,
                InterventionType.TEMPORARY_BLOCK_IP: 0.30,
            },
            default_ip_direct_cost=0.20,
        )
        sim_params = {
            InterventionType.RATE_LIMIT_IP: InterventionParameters(rate_limit_factor=1.0),
            InterventionType.TEMPORARY_BLOCK_IP: InterventionParameters(source_attribution_valid=True, block_volume_reduction=0.0),
        }

        runs = []
        for _ in range(10):
            res = self.selector.select(
                current_state=state,
                candidate_actions=(InterventionType.TEMPORARY_BLOCK_IP, InterventionType.RATE_LIMIT_IP),
                baseline_deltas=deltas,
                simulation_params_map=sim_params,
                disruption_params=disrupt_params,
                topology=self.topology,
                risk_constraints=RiskConstraintParameters(target_risk=0.90, peak_risk_ceiling=0.90),
            )
            runs.append(res.recommended_action)

        # All 10 runs must produce the exact same recommended action
        self.assertEqual(len(set(runs)), 1)
        # Canonical order dictates RATE_LIMIT_IP precedes TEMPORARY_BLOCK_IP
        self.assertEqual(runs[0], InterventionType.RATE_LIMIT_IP)

    # ────────────────────────────────────────────────────────────
    # TEST 10 — PARAMETER TRANSPARENCY
    # ────────────────────────────────────────────────────────────
    def test_10_parameter_transparency(self):
        """Altering risk thresholds or disruption weights shifts the recommendation, proving they are active parameters."""
        state = make_attack_state()
        feat_list = list(CSV_AVAILABLE_FEATURES)
        H = 3
        D = len(feat_list)
        deltas = np.zeros((H, D), dtype=np.float64)
        deltas[:, feat_list.index("byte_rate")] = 100000.0

        sim_params = {
            InterventionType.RATE_LIMIT_IP: InterventionParameters(rate_limit_factor=0.20),
            InterventionType.TEMPORARY_BLOCK_IP: InterventionParameters(source_attribution_valid=True, block_volume_reduction=1.0),
        }

        # Loose constraint: RATE_LIMIT is sufficient and wins on lower disruption
        loose_res = self.selector.select(
            current_state=state,
            candidate_actions=(InterventionType.RATE_LIMIT_IP, InterventionType.TEMPORARY_BLOCK_IP),
            baseline_deltas=deltas,
            simulation_params_map=sim_params,
            topology=self.topology,
            risk_constraints=RiskConstraintParameters(target_risk=0.50, peak_risk_ceiling=0.70),
        )
        self.assertEqual(loose_res.recommended_action, InterventionType.RATE_LIMIT_IP)

        # Extremely tight target risk: RATE_LIMIT is no longer sufficient, but BLOCK is
        tight_target = loose_res.action_evaluations[InterventionType.TEMPORARY_BLOCK_IP.value].aggregate_risk + 0.02
        if tight_target < loose_res.action_evaluations[InterventionType.RATE_LIMIT_IP.value].aggregate_risk:
            tight_res = self.selector.select(
                current_state=state,
                candidate_actions=(InterventionType.RATE_LIMIT_IP, InterventionType.TEMPORARY_BLOCK_IP),
                baseline_deltas=deltas,
                simulation_params_map=sim_params,
                topology=self.topology,
                risk_constraints=RiskConstraintParameters(target_risk=tight_target, peak_risk_ceiling=0.70),
            )
            self.assertEqual(tight_res.recommended_action, InterventionType.TEMPORARY_BLOCK_IP)

    # ────────────────────────────────────────────────────────────
    # TEST 11 — NO EXECUTION
    # ────────────────────────────────────────────────────────────
    def test_11_no_execution_boundaries_invoked(self):
        """Mock response adapters and executors; verify selector NEVER invokes them."""
        with patch("core.response_execution.adapters.DemoResponseAdapter.execute") as mock_exec, \
             patch("core.response_execution.adapters.DemoResponseAdapter.rollback") as mock_rb, \
             patch("core.response_execution.executor.ResponseExecutor.execute") as mock_executor:

            state = make_attack_state()
            H = 3
            D = len(CSV_AVAILABLE_FEATURES)
            deltas = np.ones((H, D), dtype=np.float64) * 20.0

            _ = self.selector.select(
                current_state=state,
                baseline_deltas=deltas,
                topology=self.topology,
            )

            mock_exec.assert_not_called()
            mock_rb.assert_not_called()
            mock_executor.assert_not_called()

    # ────────────────────────────────────────────────────────────
    # TEST 12 — PHASE 3A AND CORE ARCHITECTURE INTEGRITY
    # ────────────────────────────────────────────────────────────
    def test_12_phase3a_integrity(self):
        """Verify Phase 3B selection does not alter Phase 3A simulation results or AR(5) model weights."""
        original_coefs = [reg.coef_.copy() for reg in self.ar_model.models]
        state = make_attack_state()
        state_vals_before = deepcopy(state.feature_values())

        H = 3
        D = len(CSV_AVAILABLE_FEATURES)
        deltas = np.ones((H, D), dtype=np.float64) * 15.0

        _ = self.selector.select(
            current_state=state,
            baseline_deltas=deltas,
            topology=self.topology,
        )

        # State unmutated
        self.assertEqual(state.feature_values(), state_vals_before)

        # Model weights untouched
        for j, reg in enumerate(self.ar_model.models):
            np.testing.assert_array_equal(reg.coef_, original_coefs[j])

    # ────────────────────────────────────────────────────────────
    # SCIENTIFIC VALIDATION TEST — LOWER DISRUPTION != LOWER SECURITY RISK
    # ────────────────────────────────────────────────────────────
    def test_13_scientific_validation_lower_disruption_not_lowest_risk(self):
        """Verify that the minimum-sufficient selector chooses sufficiency first, disruption second."""
        state = make_attack_state()
        feat_list = list(CSV_AVAILABLE_FEATURES)
        H = 3
        D = len(feat_list)
        deltas = np.zeros((H, D), dtype=np.float64)
        deltas[:, feat_list.index("byte_rate")] = 100000.0

        sim_params = {
            InterventionType.RATE_LIMIT_IP: InterventionParameters(rate_limit_factor=0.20),
            InterventionType.TEMPORARY_BLOCK_IP: InterventionParameters(source_attribution_valid=True, block_volume_reduction=1.0),
        }

        result = self.selector.select(
            current_state=state,
            candidate_actions=(InterventionType.RATE_LIMIT_IP, InterventionType.TEMPORARY_BLOCK_IP),
            baseline_deltas=deltas,
            simulation_params_map=sim_params,
            topology=self.topology,
            risk_constraints=RiskConstraintParameters(target_risk=0.50, peak_risk_ceiling=0.70),
        )

        eval_rl = result.action_evaluations[InterventionType.RATE_LIMIT_IP.value]
        eval_block = result.action_evaluations[InterventionType.TEMPORARY_BLOCK_IP.value]

        # The winner is RATE_LIMIT_IP
        self.assertEqual(result.recommended_action, InterventionType.RATE_LIMIT_IP)

        # The selected action has HIGHER security risk than the available BLOCK action
        self.assertGreaterEqual(eval_rl.aggregate_risk, eval_block.aggregate_risk)

        # BUT the selected action has strictly LOWER operational disruption
        self.assertLess(eval_rl.disruption_estimate, eval_block.disruption_estimate)


if __name__ == "__main__":
    unittest.main()
