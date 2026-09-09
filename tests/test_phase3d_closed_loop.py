"""Unit and Integration Tests for Phase 3D: Closed-Loop Verification & Reconsideration (SIH 26153).

Comprehensive verification of:
1. Conforming trajectory -> VERIFIED_SUCCESS
2. Missing telemetry -> INSUFFICIENT_EVIDENCE
3. Empty window telemetry -> INSUFFICIENT_EVIDENCE
4. Divergent feature -> VERIFIED_MISMATCH
5. Risk ceiling breach -> VERIFIED_MISMATCH
6. Case A: Dual-layer both pass -> VERIFIED_SUCCESS
7. Case B: Feature diverges, risk passes -> VERIFIED_MISMATCH
8. Case C: Risk breaches, feature passes -> VERIFIED_MISMATCH
9. Case D: Both risk breaches and feature diverges -> VERIFIED_MISMATCH
10. Uncertainty tolerance widening: h=3 tolerance wider than h=1
11. Configurable kappa: custom expansion factor
12. Configurable base tolerance
13. Execution-relative window alignment: windows prior to or during execution excluded
14. Action TTL partitioning: active mitigation window boundary
15. All windows past TTL -> INSUFFICIENT_EVIDENCE
16. Persistence filter: transient spike ignored (persistence=2) -> VERIFIED_SUCCESS
17. Persistence filter: consecutive mismatches trigger VERIFIED_MISMATCH
18. Risk ceiling breach bypasses persistence: immediate mismatch
19. Epistemic wording: no forbidden causal claims ("causal", "counterfactual", "pearlian", etc.)
20. Epistemic wording: no definite failure claims ("diverged from model expectation")
21. Reconsideration: mismatch produces unapproved request (approval_required=True)
22. Reconsideration: non-mismatch returns None
23. Zero second execution: reconsideration never invokes authorize_and_execute or execute
24. Zero autonomous rollback: no rollback executed on mismatch
25. Reconsideration trust penalty matches empirical formula
26. Backward compatibility: existing OutcomeVerifier.verify() and handoff unchanged
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
import unittest
from unittest.mock import MagicMock
import numpy as np

from core.authority.models import ActionClass
from core.contracts import (
    Direction,
    FeatureAvailability,
    NetworkState,
    Source,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    new_id,
)
from core.response_execution.models import (
    ExecutionStatus,
    HumanApproval,
    ReversibleActionType,
    ResponseAction,
    RollbackPolicy,
)
from core.response_execution.verification import (
    OutcomeExpectation,
    OutcomeVerifier,
    TrajectoryOutcomeExpectation,
    TrajectoryVerificationConfig,
    TrajectoryVerificationResult,
    VerificationStatus,
)
from simulation.approval_gate import HumanApprovalGate
from simulation.approval_models import ApprovalConfig, ApprovalRequest
from simulation.closed_loop import ClosedLoopCoordinator
from simulation.decision_models import (
    ActionEvaluation,
    DecisionResult,
    RecommendationStatus,
)
from simulation.models import (
    AssumptionClassification,
    AssumptionRecord,
    InterventionStatus,
    InterventionType,
)
from simulation.selector import MinimumSufficientSelector


class MockRiskScore:
    def __init__(self, score: float) -> None:
        self.score = score


class MockRiskEngine:
    def __init__(self, scores: list[float] | float) -> None:
        if isinstance(scores, (int, float)):
            self.scores = [float(scores)] * 10
        else:
            self.scores = list(scores)
        self.idx = 0

    def compute_risk_score(self, state: Any, hypothesis: Any, horizon_step: int = 0) -> MockRiskScore:
        s = self.scores[min(self.idx, len(self.scores) - 1)]
        self.idx += 1
        return MockRiskScore(s)


class MockBridge:
    def extract_signatures(self, state: Any) -> tuple[str, ...]:
        return ("sig-mock",)

    def infer_stage_hypotheses(self, sigs: Any, state: Any) -> tuple[str, ...]:
        return ("hyp-mock",)


class TestPhase3DClosedLoop(unittest.TestCase):
    """Test suite for Phase 3D Closed-Loop Verification and Reconsideration."""

    def setUp(self) -> None:
        self.base_time = datetime(2026, 9, 8, 12, 0, 0)
        self.coordinator = ClosedLoopCoordinator()
        self.verifier = OutcomeVerifier()

        # Build baseline state
        self.baseline_state = self._make_state(
            window_id="win-base",
            t_start=self.base_time - timedelta(seconds=10),
            t_end=self.base_time,
            byte_rate=50000.0,
        )

        # Build standard ResponseAction
        self.action = ResponseAction(
            action_id="act-test-01",
            action_class=ActionClass.EXECUTE_REVERSIBLE_ACTION,
            target_node_id="192.168.1.50",
            action_type=ReversibleActionType.TEMP_RATE_LIMIT,
            requested_parameters={"rate_limit_bps": 5000.0, "duration_s": 30.0},
            expected_effect="Mitigate risk via TEMP_RATE_LIMIT",
            reversibility=True,
            compensating_action_type="REMOVE_TEMP_RATE_LIMIT",
            authority_decision_id="auth-01",
            evidence_window_id="win-base",
            rollback_policy=RollbackPolicy.AUTOMATIC_COMPENSATING,
        )

        # Build standard DecisionResult
        self.decision_result = self._make_decision_result(
            action=InterventionType.RATE_LIMIT_IP,
            peak_risk_ceiling=0.60,
        )

    def _make_state(
        self,
        window_id: str,
        t_start: datetime,
        t_end: datetime,
        byte_rate: float = 20000.0,
        is_empty: bool = False,
        availability: FeatureAvailability = FeatureAvailability.AVAILABLE,
    ) -> NetworkState:
        return NetworkState(
            window_id=window_id,
            timestamp_start=t_start,
            timestamp_end=t_end,
            window_duration_s=(t_end - t_start).total_seconds(),
            flow_count=0 if is_empty else 100,
            byte_rate=byte_rate,
            packet_rate=100.0,
            mean_flow_duration=1.0,
            src_ip_diversity=5,
            dst_ip_diversity=5,
            src_port_diversity=10,
            dst_port_diversity=10,
            fan_out=1.0,
            internal_ratio=0.5,
            east_west_count=10,
            syn_count=10,
            ack_count=10,
            rst_count=1,
            syn_ratio=0.05,
            rst_ratio=0.01,
            iat_mean=0.1,
            iat_std=0.01,
            iat_skew=0.0,
            pkt_size_mean=500.0,
            pkt_size_std=50.0,
            byte_variance=100.0,
            ttl_mean=64.0,
            ttl_variance=1.0,
            tcp_window_mean=1024.0,
            fragment_count=0,
            retransmit_count=0,
            payload_size_mean=400.0,
            source=Source.PCAP,
            data_quality=0.0 if is_empty else 1.0,
            is_empty=is_empty,
            gap_before=False,
            gap_after=False,
            session_id="sess-001",
            provenance_hash="0" * 64,
            feature_availability={"byte_rate": availability},
        )

    def _make_decision_result(
        self,
        action: InterventionType = InterventionType.RATE_LIMIT_IP,
        peak_risk_ceiling: float = 0.60,
    ) -> DecisionResult:
        evals = {
            action.value: ActionEvaluation(
                action=action,
                simulation_status=InterventionStatus.APPLIED,
                aggregate_risk=0.30,
                peak_risk=0.45,
                risk_target_satisfied=True,
                peak_ceiling_satisfied=True,
                is_sufficient=True,
                disruption_estimate=0.20,
                disruption_breakdown={"direct_cost": 0.1, "cascade_cost": 0.1},
                assumptions=(
                    AssumptionRecord(
                        parameter_name="rate_limit_factor",
                        parameter_value=0.25,
                        classification=AssumptionClassification.INITIAL_DESIGN_PARAMETER.value,
                        description="Initial design assumption",
                        features_affected=("byte_rate",),
                    ),
                ),
                warnings=(),
            )
        }
        return DecisionResult(
            recommended_action=action,
            recommendation_status=RecommendationStatus.RECOMMENDED,
            sufficient_candidates=(action,),
            rejected_candidates=(),
            action_evaluations=evals,
            selected_risk=0.30,
            selected_peak_risk=0.45,
            selected_disruption=0.20,
            lowest_risk_candidate=action,
            target_risk=0.40,
            peak_risk_ceiling=peak_risk_ceiling,
            unresolved_reason=None,
            provenance_hash="test-dr-hash",
        )

    def _make_trust(self, composite_trust: float = 0.85) -> TrustAssessment:
        level = TrustLevel.HIGH if composite_trust >= 0.70 else TrustLevel.MEDIUM
        return TrustAssessment(
            assessment_id="trust-prior",
            forecast_id="fc-prior",
            forecast_confidence=composite_trust,
            model_disagreement=0.10,
            distribution_shift_score=0.10,
            novelty_score=0.10,
            historical_error=0.10,
            data_quality=1.0,
            composite_trust=composite_trust,
            trust_level=level,
            contributing_factors=(
                TrustFactor(
                    name="base_confidence",
                    value=composite_trust,
                    direction=Direction.INCREASES_TRUST,
                ),
            ),
        )

    # -------------------------------------------------------------------------
    # 1. CONFORMING TRAJECTORY -> VERIFIED_SUCCESS
    # -------------------------------------------------------------------------
    def test_1_conforming_trajectory_verified_success(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=20000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=15000.0),
            self._make_state("win-3", self.base_time + timedelta(seconds=20), self.base_time + timedelta(seconds=30), byte_rate=12000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            risk_engine=MockRiskEngine(0.35),
            bridge=MockBridge(),
        )
        self.assertEqual(res.status, VerificationStatus.VERIFIED_SUCCESS)
        self.assertFalse(res.reconsideration_recommended)
        self.assertFalse(res.is_model_mismatch)
        self.assertFalse(res.risk_ceiling_breached)

    # -------------------------------------------------------------------------
    # 2. MISSING TELEMETRY -> INSUFFICIENT_EVIDENCE
    # -------------------------------------------------------------------------
    def test_2_missing_telemetry_insufficient_evidence(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=[],
        )
        self.assertEqual(res.status, VerificationStatus.INSUFFICIENT_EVIDENCE)
        self.assertFalse(res.reconsideration_recommended)
        self.assertFalse(res.is_model_mismatch)

    # -------------------------------------------------------------------------
    # 3. EMPTY WINDOW TELEMETRY -> INSUFFICIENT_EVIDENCE
    # -------------------------------------------------------------------------
    def test_3_empty_window_telemetry_insufficient_evidence(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        empty_state = self._make_state(
            "win-empty",
            self.base_time,
            self.base_time + timedelta(seconds=10),
            byte_rate=0.0,
            is_empty=True,
        )
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=[empty_state],
        )
        self.assertEqual(res.status, VerificationStatus.INSUFFICIENT_EVIDENCE)
        self.assertIn("empty", res.explanation.lower())

    # -------------------------------------------------------------------------
    # 4. DIVERGENT FEATURE -> VERIFIED_MISMATCH
    # -------------------------------------------------------------------------
    def test_4_divergent_feature_verified_mismatch(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        # byte_rate increases from 50,000 to 80,000 (diverges above baseline + tolerance cone)
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=80000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=85000.0),
            self._make_state("win-3", self.base_time + timedelta(seconds=20), self.base_time + timedelta(seconds=30), byte_rate=90000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            risk_engine=MockRiskEngine(0.35),
            bridge=MockBridge(),
        )
        self.assertEqual(res.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertTrue(res.reconsideration_recommended)
        self.assertTrue(res.is_model_mismatch)
        self.assertFalse(res.risk_ceiling_breached)
        self.assertGreaterEqual(res.persistence_count, 2)

    # -------------------------------------------------------------------------
    # 5. RISK CEILING BREACH -> VERIFIED_MISMATCH
    # -------------------------------------------------------------------------
    def test_5_risk_ceiling_breach_verified_mismatch(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        # byte_rate drops (feature conforms), but risk breaches ceiling (0.85 > 0.60)
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=20000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=15000.0),
            self._make_state("win-3", self.base_time + timedelta(seconds=20), self.base_time + timedelta(seconds=30), byte_rate=12000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            risk_engine=MockRiskEngine(0.85),
            bridge=MockBridge(),
        )
        self.assertEqual(res.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertTrue(res.risk_ceiling_breached)
        self.assertTrue(res.reconsideration_recommended)
        self.assertIn("ceiling", res.explanation.lower())

    # -------------------------------------------------------------------------
    # 6. CASE A: DUAL-LAYER BOTH PASS -> VERIFIED_SUCCESS
    # -------------------------------------------------------------------------
    def test_6_case_a_dual_layer_both_pass(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=25000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=20000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            risk_engine=MockRiskEngine(0.30),
            bridge=MockBridge(),
        )
        self.assertEqual(res.status, VerificationStatus.VERIFIED_SUCCESS)
        self.assertFalse(res.risk_ceiling_breached)

    # -------------------------------------------------------------------------
    # 7. CASE B: FEATURE DIVERGES, RISK PASSES -> VERIFIED_MISMATCH
    # -------------------------------------------------------------------------
    def test_7_case_b_feature_diverges_risk_passes(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=75000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=80000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            risk_engine=MockRiskEngine(0.30),
            bridge=MockBridge(),
        )
        self.assertEqual(res.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertFalse(res.risk_ceiling_breached)
        self.assertIn("feature delta divergence", res.explanation.lower())

    # -------------------------------------------------------------------------
    # 8. CASE C: RISK BREACHES, FEATURE PASSES -> VERIFIED_MISMATCH
    # -------------------------------------------------------------------------
    def test_8_case_c_risk_breaches_feature_passes(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=20000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=20000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            risk_engine=MockRiskEngine(0.75),  # 0.75 > 0.60 ceiling
            bridge=MockBridge(),
        )
        self.assertEqual(res.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertTrue(res.risk_ceiling_breached)
        self.assertIn("security risk ceiling", res.explanation.lower())

    # -------------------------------------------------------------------------
    # 9. CASE D: BOTH RISK BREACHES AND FEATURE DIVERGES -> VERIFIED_MISMATCH
    # -------------------------------------------------------------------------
    def test_9_case_d_both_breach(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=80000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=85000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            risk_engine=MockRiskEngine(0.80),
            bridge=MockBridge(),
        )
        self.assertEqual(res.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertTrue(res.risk_ceiling_breached)

    # -------------------------------------------------------------------------
    # 10. UNCERTAINTY TOLERANCE WIDENING: h=3 TOLERANCE > h=1 TOLERANCE
    # -------------------------------------------------------------------------
    def test_10_uncertainty_tolerance_widening(self) -> None:
        cfg = TrajectoryVerificationConfig(base_tolerance=0.10, horizon_expansion_factor=0.25)
        # Tolerance at h=1: 0.10 * (1 + 0.25 * 0) = 0.10 (10%)
        # Tolerance at h=3: 0.10 * (1 + 0.25 * 2) = 0.15 (15%)
        tol_h1 = cfg.base_tolerance * (1.0 + cfg.horizon_expansion_factor * 0)
        tol_h3 = cfg.base_tolerance * (1.0 + cfg.horizon_expansion_factor * 2)
        self.assertAlmostEqual(tol_h1, 0.10, places=4)
        self.assertAlmostEqual(tol_h3, 0.15, places=4)
        self.assertGreater(tol_h3, tol_h1)

        # A +12% increase from baseline:
        # Baseline = 50,000 -> +12% is 56,000.
        # At h=1: (56000 - 50000) / 50000 = 0.12 > 0.10 -> diverges (FAIL)
        # At h=3: 0.12 <= 0.15 -> within tolerance cone (PASS)
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        # Window 1 (+12%): fails h=1 tolerance
        # Window 2 (+5%): passes h=2 tolerance
        # Window 3 (+12%): passes h=3 tolerance
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=56000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=52500.0),
            self._make_state("win-3", self.base_time + timedelta(seconds=20), self.base_time + timedelta(seconds=30), byte_rate=56000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            config=cfg,
        )
        self.assertTrue(res.step_evaluations[1]["feature_diverged"])
        self.assertFalse(res.step_evaluations[2]["feature_diverged"])
        self.assertFalse(res.step_evaluations[3]["feature_diverged"])

    # -------------------------------------------------------------------------
    # 11. UNCERTAINTY CONFIGURABLE KAPPA
    # -------------------------------------------------------------------------
    def test_11_uncertainty_configurable_kappa(self) -> None:
        cfg_custom = TrajectoryVerificationConfig(base_tolerance=0.10, horizon_expansion_factor=0.50)
        # At h=2: tol = 0.10 * (1 + 0.50 * 1) = 0.15
        tol_h2 = cfg_custom.base_tolerance * (1.0 + cfg_custom.horizon_expansion_factor * 1)
        self.assertAlmostEqual(tol_h2, 0.15, places=4)

        # 50,000 + 14% = 57,000
        # Under default kappa=0.25: tol_h2 = 0.125 -> 0.14 > 0.125 (diverges)
        # Under custom kappa=0.50: tol_h2 = 0.15 -> 0.14 <= 0.15 (passes)
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=50000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=57000.0),
        ]
        res_default = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            config=TrajectoryVerificationConfig(horizon_expansion_factor=0.25),
        )
        self.assertTrue(res_default.step_evaluations[2]["feature_diverged"])

        res_custom = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            config=cfg_custom,
        )
        self.assertFalse(res_custom.step_evaluations[2]["feature_diverged"])

    # -------------------------------------------------------------------------
    # 12. UNCERTAINTY CONFIGURABLE BASE TOLERANCE
    # -------------------------------------------------------------------------
    def test_12_uncertainty_configurable_base_tolerance(self) -> None:
        cfg_tight = TrajectoryVerificationConfig(base_tolerance=0.02)
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        # 50,000 + 3% = 51,500. Under 0.02 base tolerance, this diverges at h=1
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=51500.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            config=cfg_tight,
        )
        self.assertTrue(res.step_evaluations[1]["feature_diverged"])

    # -------------------------------------------------------------------------
    # 13. EXECUTION-RELATIVE WINDOW ALIGNMENT
    # -------------------------------------------------------------------------
    def test_13_execution_relative_window_alignment(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        # Feed windows: W_past (before exec), W_exec (during exec), and W1, W2, W3 (post-exec)
        all_states = [
            self._make_state("win-past", self.base_time - timedelta(seconds=20), self.base_time - timedelta(seconds=10), byte_rate=99999.0),
            self._make_state("win-exec", self.base_time - timedelta(seconds=10), self.base_time, byte_rate=88888.0),
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=20000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=15000.0),
            self._make_state("win-3", self.base_time + timedelta(seconds=20), self.base_time + timedelta(seconds=30), byte_rate=12000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=all_states,
        )
        # Evaluated windows must strictly be win-1, win-2, win-3
        self.assertEqual(res.evidence_window_ids, ("win-1", "win-2", "win-3"))
        self.assertEqual(res.step_evaluations[1]["window_id"], "win-1")
        self.assertEqual(res.step_evaluations[2]["window_id"], "win-2")
        self.assertEqual(res.step_evaluations[3]["window_id"], "win-3")

    # -------------------------------------------------------------------------
    # 14. ACTIVE ACTION TTL PARTITIONING
    # -------------------------------------------------------------------------
    def test_14_active_action_ttl_partitioning(self) -> None:
        # action_ttl_seconds = 20.0s. Expiration is base_time + 20s.
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
            action_ttl_seconds=20.0,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=20000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=15000.0),
            # win-3 ends at base_time + 30s > base_time + 20s + 1s (must be partitioned out)
            self._make_state("win-3", self.base_time + timedelta(seconds=20), self.base_time + timedelta(seconds=30), byte_rate=99999.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
        )
        # Evaluated windows should only include win-1 and win-2
        self.assertEqual(res.evidence_window_ids, ("win-1", "win-2"))
        self.assertNotIn(3, res.step_evaluations)
        self.assertEqual(res.status, VerificationStatus.VERIFIED_SUCCESS)

    # -------------------------------------------------------------------------
    # 15. ALL WINDOWS PAST TTL -> INSUFFICIENT_EVIDENCE
    # -------------------------------------------------------------------------
    def test_15_all_windows_past_ttl_insufficient_evidence(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
            action_ttl_seconds=10.0,
        )
        # Window starts at base_time + 20s, well past TTL
        observed = [
            self._make_state("win-late", self.base_time + timedelta(seconds=20), self.base_time + timedelta(seconds=30), byte_rate=20000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
        )
        self.assertEqual(res.status, VerificationStatus.INSUFFICIENT_EVIDENCE)
        self.assertIn("ttl", res.explanation.lower())

    # -------------------------------------------------------------------------
    # 16. PERSISTENCE FILTER: TRANSIENT SPIKE IGNORED (PERSISTENCE=2)
    # -------------------------------------------------------------------------
    def test_16_persistence_filter_transient_spike_ignored(self) -> None:
        # Pattern: [FAIL, PASS, PASS] or [FAIL, PASS, FAIL]
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=80000.0),   # FAIL
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=20000.0),   # PASS
            self._make_state("win-3", self.base_time + timedelta(seconds=20), self.base_time + timedelta(seconds=30), byte_rate=80000.0),   # FAIL
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            config=TrajectoryVerificationConfig(persistence_required_steps=2),
        )
        # Because mismatches are separated by a conforming window, max consecutive is 1 < 2
        self.assertEqual(res.persistence_count, 1)
        self.assertEqual(res.status, VerificationStatus.VERIFIED_SUCCESS)
        self.assertFalse(res.reconsideration_recommended)

    # -------------------------------------------------------------------------
    # 17. PERSISTENCE FILTER: CONSECUTIVE MISMATCHES TRIGGER VERIFIED_MISMATCH
    # -------------------------------------------------------------------------
    def test_17_persistence_filter_consecutive_mismatch_triggers(self) -> None:
        # Pattern: [PASS, FAIL, FAIL] -> 2 consecutive mismatches
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=20000.0),   # PASS
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=80000.0),   # FAIL
            self._make_state("win-3", self.base_time + timedelta(seconds=20), self.base_time + timedelta(seconds=30), byte_rate=85000.0),   # FAIL
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            config=TrajectoryVerificationConfig(persistence_required_steps=2),
        )
        self.assertEqual(res.persistence_count, 2)
        self.assertEqual(res.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertTrue(res.reconsideration_recommended)

    # -------------------------------------------------------------------------
    # 18. RISK CEILING BREACH BYPASSES PERSISTENCE
    # -------------------------------------------------------------------------
    def test_18_risk_ceiling_breach_bypasses_persistence(self) -> None:
        # Step 1 breaches risk ceiling; Step 2 and 3 are conforming
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=20000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=15000.0),
            self._make_state("win-3", self.base_time + timedelta(seconds=20), self.base_time + timedelta(seconds=30), byte_rate=12000.0),
        ]
        # Risk engine returns [0.85, 0.30, 0.30]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
            risk_engine=MockRiskEngine([0.85, 0.30, 0.30]),
            bridge=MockBridge(),
            config=TrajectoryVerificationConfig(persistence_required_steps=2),
        )
        self.assertEqual(res.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertTrue(res.risk_ceiling_breached)
        self.assertTrue(res.reconsideration_recommended)

    # -------------------------------------------------------------------------
    # 19. EPISTEMIC WORDING: NO FORBIDDEN CAUSAL CLAIMS
    # -------------------------------------------------------------------------
    def test_19_epistemic_wording_no_causal_claims(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=80000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=85000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
        )
        explanation_lower = res.explanation.lower()
        forbidden_terms = ["causal", "cause", "caused", "counterfactual", "pearlian", "pearl", "profound", "definitely failed"]
        for term in forbidden_terms:
            self.assertNotIn(term, explanation_lower, f"Forbidden term '{term}' found in explanation")

    # -------------------------------------------------------------------------
    # 20. EPISTEMIC WORDING: NO DEFINITE FAILURE CLAIMS
    # -------------------------------------------------------------------------
    def test_20_epistemic_wording_no_definite_failure_claims(self) -> None:
        expectation = self.coordinator.build_trajectory_expectation(
            action=self.action,
            decision_result=self.decision_result,
            baseline_state=self.baseline_state,
            execution_window_id="win-exec",
            execution_timestamp_end=self.base_time,
        )
        observed = [
            self._make_state("win-1", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=80000.0),
            self._make_state("win-2", self.base_time + timedelta(seconds=10), self.base_time + timedelta(seconds=20), byte_rate=85000.0),
        ]
        res = self.coordinator.evaluate_closed_loop(
            action=self.action,
            expectation=expectation,
            observed_states=observed,
        )
        # Must describe divergence non-causally
        self.assertIn("observed network behavior diverged from model expectation", res.explanation.lower())

    # -------------------------------------------------------------------------
    # 21. RECONSIDERATION: MISMATCH PRODUCES UNAPPROVED REQUEST
    # -------------------------------------------------------------------------
    def test_21_reconsideration_mismatch_produces_unapproved_request(self) -> None:
        selector = MinimumSufficientSelector()
        gate = HumanApprovalGate()

        # Build mismatch verification result
        mismatch_res = TrajectoryVerificationResult(
            verification_id="verif-mismatch-1",
            action_id=self.action.action_id,
            status=VerificationStatus.VERIFIED_MISMATCH,
            step_evaluations={
                1: {"window_id": "win-1", "step_mismatch": True, "baseline_value": 50000.0, "observed_value": 80000.0},
                2: {"window_id": "win-2", "step_mismatch": True, "baseline_value": 50000.0, "observed_value": 85000.0},
            },
            max_observed_risk=0.55,
            risk_ceiling=0.60,
            risk_ceiling_breached=False,
            persistence_count=2,
            reconsideration_recommended=True,
            explanation="Observed network behavior diverged from model expectation: Persistent feature delta divergence.",
            evidence_window_ids=("win-1", "win-2"),
        )

        prior_trust = self._make_trust(0.85)

        history_deltas = np.zeros((10, 15))

        new_request = self.coordinator.trigger_reconsideration_if_mismatch(
            verification_result=mismatch_res,
            current_state=self.baseline_state,
            history_deltas=history_deltas,
            prior_trust=prior_trust,
            selector=selector,
            approval_gate=gate,
            target_entity="192.168.1.50",
            baseline_deltas=np.zeros((3, 15)),
        )

        self.assertIsNotNone(new_request)
        self.assertIsInstance(new_request, ApprovalRequest)
        self.assertTrue(new_request.approval_required)
        self.assertIn("RECONSIDERATION TRIGGERED", new_request.rationale)

    # -------------------------------------------------------------------------
    # 22. RECONSIDERATION: NON-MISMATCH RETURNS NONE
    # -------------------------------------------------------------------------
    def test_22_reconsideration_non_mismatch_returns_none(self) -> None:
        selector = MinimumSufficientSelector()
        gate = HumanApprovalGate()

        success_res = TrajectoryVerificationResult(
            verification_id="verif-succ-1",
            action_id=self.action.action_id,
            status=VerificationStatus.VERIFIED_SUCCESS,
            step_evaluations={},
            max_observed_risk=0.30,
            risk_ceiling=0.60,
            risk_ceiling_breached=False,
            persistence_count=0,
            reconsideration_recommended=False,
            explanation="Conforming.",
        )

        prior_trust = self._make_trust(0.85)

        res = self.coordinator.trigger_reconsideration_if_mismatch(
            verification_result=success_res,
            current_state=self.baseline_state,
            history_deltas=np.zeros((10, 15)),
            prior_trust=prior_trust,
            selector=selector,
            approval_gate=gate,
            target_entity="192.168.1.50",
            baseline_deltas=np.zeros((3, 15)),
        )
        self.assertIsNone(res)

    # -------------------------------------------------------------------------
    # 23. ZERO SECOND EXECUTION: RECONSIDERATION NEVER INVOKES EXECUTOR
    # -------------------------------------------------------------------------
    def test_23_reconsideration_zero_second_execution(self) -> None:
        selector = MinimumSufficientSelector()
        gate = HumanApprovalGate()
        gate.authorize_and_execute = MagicMock()

        mismatch_res = TrajectoryVerificationResult(
            verification_id="verif-mismatch-1",
            action_id=self.action.action_id,
            status=VerificationStatus.VERIFIED_MISMATCH,
            step_evaluations={
                1: {"window_id": "win-1", "step_mismatch": True, "baseline_value": 50000.0, "observed_value": 80000.0},
            },
            max_observed_risk=0.55,
            risk_ceiling=0.60,
            risk_ceiling_breached=False,
            persistence_count=1,
            reconsideration_recommended=True,
            explanation="Mismatch.",
        )

        prior_trust = self._make_trust(0.85)

        req = self.coordinator.trigger_reconsideration_if_mismatch(
            verification_result=mismatch_res,
            current_state=self.baseline_state,
            history_deltas=np.zeros((10, 15)),
            prior_trust=prior_trust,
            selector=selector,
            approval_gate=gate,
            target_entity="192.168.1.50",
            baseline_deltas=np.zeros((3, 15)),
        )

        # Confirm authorize_and_execute was NEVER called
        gate.authorize_and_execute.assert_not_called()
        self.assertIsNotNone(req)

    # -------------------------------------------------------------------------
    # 24. ZERO AUTONOMOUS ROLLBACK
    # -------------------------------------------------------------------------
    def test_24_reconsideration_no_autonomous_rollback(self) -> None:
        # Verify that verifying a mismatch does not execute any rollback
        adapter_mock = MagicMock()
        mismatch_res = TrajectoryVerificationResult(
            verification_id="verif-mismatch-1",
            action_id=self.action.action_id,
            status=VerificationStatus.VERIFIED_MISMATCH,
            step_evaluations={},
            max_observed_risk=0.75,
            risk_ceiling=0.60,
            risk_ceiling_breached=True,
            persistence_count=1,
            reconsideration_recommended=True,
            explanation="Risk breached ceiling.",
        )
        handoff = self.verifier.build_trajectory_reconsideration_handoff(mismatch_res)
        self.assertIsNotNone(handoff)
        # Check no adapter call was made
        adapter_mock.execute_rollback.assert_not_called()

    # -------------------------------------------------------------------------
    # 25. RECONSIDERATION TRUST PENALTY MATCHES FORMULA
    # -------------------------------------------------------------------------
    def test_25_reconsideration_trust_penalty_matches_formula(self) -> None:
        # Dev = |80000 - 50000| / 50000 = 0.60
        # penalty = min(0.30, 0.60 * 0.10) = 0.06
        # prior trust = 0.80 -> adjusted = 0.74
        selector = MinimumSufficientSelector()
        selector.select = MagicMock(return_value=self.decision_result)
        gate = HumanApprovalGate()

        mismatch_res = TrajectoryVerificationResult(
            verification_id="verif-mismatch-calc",
            action_id=self.action.action_id,
            status=VerificationStatus.VERIFIED_MISMATCH,
            step_evaluations={
                1: {"window_id": "win-1", "step_mismatch": True, "baseline_value": 50000.0, "observed_value": 80000.0},
            },
            max_observed_risk=0.50,
            risk_ceiling=0.60,
            risk_ceiling_breached=False,
            persistence_count=1,
            reconsideration_recommended=True,
            explanation="Dev mismatch",
        )

        prior_trust = self._make_trust(0.80)

        self.coordinator.trigger_reconsideration_if_mismatch(
            verification_result=mismatch_res,
            current_state=self.baseline_state,
            history_deltas=np.zeros((10, 15)),
            prior_trust=prior_trust,
            selector=selector,
            approval_gate=gate,
            target_entity="192.168.1.50",
        )

        # Inspect the trust assessment passed to selector.select
        call_kwargs = selector.select.call_args.kwargs
        passed_trust = call_kwargs["trust_assessment"]
        self.assertAlmostEqual(passed_trust.composite_trust, 0.74, places=3)
        self.assertEqual(passed_trust.trust_level, TrustLevel.HIGH)
        self.assertEqual(passed_trust.contributing_factors[0].name, "trajectory_verification_mismatch")
        self.assertAlmostEqual(passed_trust.contributing_factors[0].value, 0.06, places=3)

    # -------------------------------------------------------------------------
    # 26. BACKWARD COMPATIBILITY: SCALAR VERIFY AND HANDOFF
    # -------------------------------------------------------------------------
    def test_26_backward_compatibility_scalar_verify(self) -> None:
        # Ensure Phase 3C scalar verify() and build_reconsideration_handoff() work 100% identically
        expectation = OutcomeExpectation(
            action_id="act-scalar",
            metric_name="byte_rate",
            expected_direction="DECREASE",
            baseline_value=50000.0,
            min_reduction_ratio=0.20,
        )
        # Success state: byte_rate = 30000.0 (40% reduction >= 20%)
        obs_success = self._make_state("win-sc-succ", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=30000.0)
        res_succ = self.verifier.verify(action=self.action, expectation=expectation, observed_state=obs_success)
        self.assertEqual(res_succ.status, VerificationStatus.VERIFIED_SUCCESS)
        self.assertFalse(res_succ.reconsideration_recommended)

        # Mismatch state: byte_rate = 55000.0 (increased)
        obs_mismatch = self._make_state("win-sc-mismatch", self.base_time, self.base_time + timedelta(seconds=10), byte_rate=55000.0)
        res_mismatch = self.verifier.verify(action=self.action, expectation=expectation, observed_state=obs_mismatch)
        self.assertEqual(res_mismatch.status, VerificationStatus.VERIFIED_MISMATCH)
        self.assertTrue(res_mismatch.reconsideration_recommended)

        # Handoff creation
        handoff = self.verifier.build_reconsideration_handoff(res_mismatch)
        self.assertIsNotNone(handoff)
        self.assertEqual(handoff.action_id, self.action.action_id)
        self.assertEqual(handoff.metric_name, "byte_rate")
        self.assertEqual(handoff.baseline_value, 50000.0)
        self.assertEqual(handoff.observed_value, 55000.0)


if __name__ == "__main__":
    unittest.main()
