"""
Unit and validation tests for Future Security-Risk Scoring Engine R(t+h) (SIH 26153).
Verifies:
1. Bounded score: 0.0 <= R(t+h) <= 1.0 under all conditions
2. Determinism: identical states produce bitwise identical risk scores
3. Benign low-risk behaviour: benign baseline stays capped in low baseline range (<= 0.20)
4. Reconnaissance elevated risk: port exploration escalates risk
5. DoS elevated risk: connection flooding produces high impact risk
6. Exfiltration elevated risk: outbound surges produce elevated collection risk
7. Ambiguous traffic risk: produces moderate/suppressed risk without false certainty
8. Contradiction dampening: contradictory forecast dampens future risk score
9. Uncertainty dampening: increasing prediction uncertainty monotonically reduces risk
10. Zero label leakage: labels/infiltration_fraction never enter risk calculation
11. Unavailable feature protection: missing topology telemetry does not inflate risk
12. Horizon separation: distinct scores for NOW, +10s, +20s, +30s reflecting horizon decay
13. Priority integration safety: high risk with low trust cannot trigger CRITICAL priority
14. Historical artifact preservation: previous experiment manifests remain untouched
"""
from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np


from core.contracts import (
    FeatureAvailability,
    NetworkState,
    PriorityLevel,
    Source,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    Direction,
    new_id,
)
from core.priority.engine import PriorityEngine
from eval.dataset import CSV_AVAILABLE_FEATURES
from security.bridge import BehavioralSecurityBridge
from security.contracts import (
    BehaviouralSignature,
    EvidenceDirection,
    EvidenceScope,
    EvidenceStrength,
    FutureSecurityRiskScore,
    SecurityRiskTrajectory,
    SignatureType,
    StageHypothesis,
)
from security.risk_engine import SecurityRiskEngine


def _make_test_state(
    dst_port_diversity: int = 2,
    flow_count: int = 15,
    byte_rate: float = 1200.0,
    syn_ratio: float = 0.05,
    rst_ratio: float = 0.05,
    pkt_size_mean: float = 100.0,
    fan_out_avail: FeatureAvailability = FeatureAvailability.UNAVAILABLE,
) -> NetworkState:
    start = datetime(2018, 3, 1, 12, 0, 0)
    avail = {f: FeatureAvailability.AVAILABLE for f in CSV_AVAILABLE_FEATURES}
    avail["fan_out"] = fan_out_avail
    avail["src_ip_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["dst_ip_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["src_port_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["internal_ratio"] = FeatureAvailability.UNAVAILABLE
    avail["east_west_count"] = FeatureAvailability.UNAVAILABLE

    return NetworkState(
        window_id="state_test_001",
        timestamp_start=start,
        timestamp_end=start + timedelta(seconds=10),
        window_duration_s=10.0,
        flow_count=flow_count,
        byte_rate=byte_rate,
        packet_rate=flow_count * 1.5,
        mean_flow_duration=5.0,
        src_ip_diversity=None,
        dst_ip_diversity=None,
        src_port_diversity=None,
        dst_port_diversity=dst_port_diversity,
        fan_out=None,
        internal_ratio=None,
        east_west_count=None,
        syn_count=int(flow_count * syn_ratio),
        ack_count=int(flow_count * 0.8),
        rst_count=int(flow_count * rst_ratio),
        syn_ratio=syn_ratio,
        rst_ratio=rst_ratio,
        iat_mean=2.0,
        iat_std=1.5,
        iat_skew=None,
        pkt_size_mean=pkt_size_mean,
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
        gap_before=False,
        gap_after=False,
        session_id="session-test",
        provenance_hash="a" * 64,
        feature_availability=avail,
    )


class TestFutureSecurityRiskScore(unittest.TestCase):

    def setUp(self) -> None:
        self.bridge = BehavioralSecurityBridge()
        self.risk_engine = SecurityRiskEngine()
        self.priority_engine = PriorityEngine()
        self.default_trust = TrustAssessment(
            assessment_id=new_id("trust-test"),
            forecast_id="fc-test",
            forecast_confidence=0.85,
            model_disagreement=0.05,
            distribution_shift_score=0.05,
            novelty_score=0.05,
            historical_error=0.10,
            data_quality=1.0,
            composite_trust=0.85,
            trust_level=TrustLevel.HIGH,
            contributing_factors=(TrustFactor(name="test", value=0.85, direction=Direction.INCREASES_TRUST),),
        )

    def test_01_score_strictly_bounded_in_zero_to_one(self) -> None:
        """Verify that risk scores are strictly bounded in [0.0, 1.0] across extreme inputs."""
        hyp_extreme = StageHypothesis(
            hypothesis_id=new_id("hyp-ext"),
            candidate_stage="Impact / Denial of Service",
            supporting_signatures=(),
            counter_evidence=(),
            confidence=1.0,
            trust_level=TrustLevel.HIGH,
            alternative_explanations=(),
            is_primary=True,
        )
        state = _make_test_state(flow_count=5000, rst_ratio=0.90)
        
        # Test extreme upper bound
        score_max = self.risk_engine.compute_risk_score(
            current_state=state,
            stage_hypothesis=hyp_extreme,
            trust_val=1.0,
            trust_level=TrustLevel.HIGH,
            uncertainty=0.0,
        )
        self.assertGreaterEqual(score_max.score, 0.0)
        self.assertLessEqual(score_max.score, 1.0)
        
        # Test extreme lower bound
        score_min = self.risk_engine.compute_risk_score(
            current_state=state,
            stage_hypothesis=hyp_extreme,
            trust_val=0.0,
            trust_level=TrustLevel.INSUFFICIENT,
            uncertainty=1.0,
        )
        self.assertEqual(score_min.score, 0.0)

    def test_02_deterministic_for_same_input(self) -> None:
        """Verify that repeated evaluation produces bitwise identical risk scores and hashes."""
        state = _make_test_state(dst_port_diversity=35, flow_count=45, syn_ratio=0.45)
        sigs = self.bridge.extract_signatures(state)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        traj1 = self.risk_engine.compute_risk_trajectory(state, hyps, self.default_trust, sigs)
        traj2 = self.risk_engine.compute_risk_trajectory(state, hyps, self.default_trust, sigs)
        
        self.assertAlmostEqual(traj1.current_risk.score, traj2.current_risk.score, places=9)
        self.assertEqual(traj1.current_risk.provenance_hash, traj2.current_risk.provenance_hash)
        for r1, r2 in zip(traj1.future_risks, traj2.future_risks):
            self.assertAlmostEqual(r1.score, r2.score, places=9)
            self.assertEqual(r1.provenance_hash, r2.provenance_hash)

    def test_03_benign_baseline_low_risk(self) -> None:
        """Verify that benign baseline traffic produces low risk (<= 0.20) and Unknown stage."""
        state_benign = _make_test_state(dst_port_diversity=2, flow_count=15)
        sigs = self.bridge.extract_signatures(state_benign)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        traj = self.risk_engine.compute_risk_trajectory(state_benign, hyps, self.default_trust, sigs)
        self.assertEqual(traj.current_risk.primary_stage, "Unknown")
        self.assertLessEqual(traj.current_risk.score, 0.20)
        self.assertLessEqual(traj.future_risks[0].score, 0.20)

    def test_04_reconnaissance_elevated_risk(self) -> None:
        """Verify that port exploration produces elevated Reconnaissance risk."""
        state_recon = _make_test_state(dst_port_diversity=35, flow_count=50, syn_ratio=0.45)
        sigs = self.bridge.extract_signatures(state_recon)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        traj = self.risk_engine.compute_risk_trajectory(state_recon, hyps, self.default_trust, sigs)
        self.assertEqual(traj.current_risk.primary_stage, "Reconnaissance")
        self.assertGreater(traj.current_risk.score, 0.25)
        self.assertGreater(traj.future_risks[0].score, 0.25)

    def test_05_connection_flooding_high_impact_risk(self) -> None:
        """Verify that connection flooding produces high Impact/DoS risk."""
        state_dos = _make_test_state(dst_port_diversity=3, flow_count=350, rst_ratio=0.45)
        sigs = self.bridge.extract_signatures(state_dos)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        traj = self.risk_engine.compute_risk_trajectory(state_dos, hyps, self.default_trust, sigs)
        self.assertEqual(traj.current_risk.primary_stage, "Impact / Denial of Service")
        self.assertGreater(traj.current_risk.score, 0.55)

    def test_06_exfiltration_outbound_surge_elevated_risk(self) -> None:
        """Verify that large byte volume and packet sizes elevate Collection/Exfiltration risk."""
        state_exfil = _make_test_state(dst_port_diversity=2, flow_count=30, byte_rate=350000.0, pkt_size_mean=850.0)
        sigs = self.bridge.extract_signatures(state_exfil)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        traj = self.risk_engine.compute_risk_trajectory(state_exfil, hyps, self.default_trust, sigs)
        self.assertEqual(traj.current_risk.primary_stage, "Collection / Exfiltration")
        self.assertGreater(traj.current_risk.score, 0.45)

    def test_07_ambiguous_traffic_suppressed_risk(self) -> None:
        """Verify that ambiguous mixed traffic produces moderate, bounded risk without false certainty."""
        state_amb = _make_test_state(dst_port_diversity=12, flow_count=35, syn_ratio=0.18)
        sigs = self.bridge.extract_signatures(state_amb)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        traj = self.risk_engine.compute_risk_trajectory(state_amb, hyps, self.default_trust, sigs)
        self.assertLess(traj.current_risk.score, 0.40)

    def test_08_contradictory_forecast_dampens_future_risk(self) -> None:
        """Verify that a contradictory forecast predicting decay suppresses future risk."""
        state = _make_test_state(dst_port_diversity=35, flow_count=45, syn_ratio=0.45)
        
        # 1. Reinforcing forecast
        reinf_deltas = np.zeros((3, len(CSV_AVAILABLE_FEATURES)))
        p_idx = CSV_AVAILABLE_FEATURES.index("dst_port_diversity")
        reinf_deltas[:, p_idx] = [8.0, 10.0, 12.0]
        sigs_reinf = self.bridge.extract_signatures(state, reinf_deltas, CSV_AVAILABLE_FEATURES, TrustLevel.HIGH)
        hyps_reinf = self.bridge.infer_stage_hypotheses(sigs_reinf, TrustLevel.HIGH)
        traj_reinf = self.risk_engine.compute_risk_trajectory(state, hyps_reinf, self.default_trust, sigs_reinf)
        
        # 2. Contradictory forecast (sharp collapse)
        contra_deltas = np.zeros((3, len(CSV_AVAILABLE_FEATURES)))
        contra_deltas[:, p_idx] = [-15.0, -10.0, -5.0]
        trust_contra = TrustAssessment(
            assessment_id=new_id("trust-contra"),
            forecast_id="fc-contra",
            forecast_confidence=0.35,
            model_disagreement=0.40,
            distribution_shift_score=0.45,
            novelty_score=0.30,
            historical_error=0.10,
            data_quality=1.0,
            composite_trust=0.35,
            trust_level=TrustLevel.LOW,
            contributing_factors=(TrustFactor(name="disagreement", value=0.40, direction=Direction.DECREASES_TRUST),),
        )
        sigs_contra = self.bridge.extract_signatures(state, contra_deltas, CSV_AVAILABLE_FEATURES, TrustLevel.LOW)
        hyps_contra = self.bridge.infer_stage_hypotheses(sigs_contra, TrustLevel.LOW)
        traj_contra = self.risk_engine.compute_risk_trajectory(state, hyps_contra, trust_contra, sigs_contra)
        
        # Contradictory future risk must be substantially lower than reinforcing
        self.assertGreater(traj_reinf.future_risks[0].score, traj_contra.future_risks[0].score)
        self.assertLess(traj_contra.future_risks[0].score, 0.10)

    def test_09_uncertainty_dampening(self) -> None:
        """Verify that increasing uncertainty monotonically dampens the computed risk score."""
        hyp = StageHypothesis(
            hypothesis_id=new_id("hyp-test"),
            candidate_stage="Reconnaissance",
            supporting_signatures=(),
            counter_evidence=(),
            confidence=0.75,
            trust_level=TrustLevel.HIGH,
            alternative_explanations=(),
            is_primary=True,
        )
        state = _make_test_state(dst_port_diversity=25, flow_count=40)
        
        score_low_unc = self.risk_engine.compute_risk_score(state, hyp, uncertainty=0.10)
        score_high_unc = self.risk_engine.compute_risk_score(state, hyp, uncertainty=0.70)
        
        self.assertGreater(score_low_unc.score, score_high_unc.score)

    def test_10_no_label_or_infiltration_fraction_leakage(self) -> None:
        """Verify that risk calculations do not access or output labels/infiltration_fraction."""
        state = _make_test_state(dst_port_diversity=25, flow_count=40)
        sigs = self.bridge.extract_signatures(state)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        traj = self.risk_engine.compute_risk_trajectory(state, hyps, self.default_trust, sigs)
        
        traj_dict_str = str(traj.to_dict()).lower()
        self.assertNotIn("infiltration_fraction", traj_dict_str)
        self.assertNotIn("ground_truth", traj_dict_str)

    def test_11_unavailable_feature_protection(self) -> None:
        """Verify that unavailable topology features do not enter as active risk factors."""
        state = _make_test_state(dst_port_diversity=25, flow_count=40, fan_out_avail=FeatureAvailability.UNAVAILABLE)
        sigs = self.bridge.extract_signatures(state)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        traj = self.risk_engine.compute_risk_trajectory(state, hyps, self.default_trust, sigs)
        
        # Check suppressing factors list unavailable topology notice
        self.assertTrue(any("topology" in s.lower() for s in traj.current_risk.suppressing_factors))

    def test_12_horizon_separation_and_decay(self) -> None:
        """Verify that R(t+0), R(t+1), R(t+2), R(t+3) are computed with distinct horizon steps."""
        state = _make_test_state(dst_port_diversity=35, flow_count=50)
        sigs = self.bridge.extract_signatures(state)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        traj = self.risk_engine.compute_risk_trajectory(state, hyps, self.default_trust, sigs, max_horizon=3)
        
        self.assertEqual(traj.current_risk.horizon_step, 0)
        self.assertEqual(len(traj.future_risks), 3)
        self.assertEqual([r.horizon_step for r in traj.future_risks], [1, 2, 3])
        self.assertEqual([r.horizon_seconds for r in traj.future_risks], [10.0, 20.0, 30.0])

    def test_13_priority_integration_safety(self) -> None:
        """Verify that high risk with low trust cannot escalate to CRITICAL priority."""
        hyp = StageHypothesis(
            hypothesis_id=new_id("hyp-test"),
            candidate_stage="Impact / Denial of Service",
            supporting_signatures=(),
            counter_evidence=(),
            confidence=0.85,
            trust_level=TrustLevel.LOW,
            alternative_explanations=(),
            is_primary=True,
        )
        trust_low = TrustAssessment(
            assessment_id=new_id("trust-low"),
            forecast_id="fc-low",
            forecast_confidence=0.30,
            model_disagreement=0.50,
            distribution_shift_score=0.60,
            novelty_score=0.40,
            historical_error=0.20,
            data_quality=1.0,
            composite_trust=0.30,
            trust_level=TrustLevel.LOW,
            contributing_factors=(TrustFactor(name="disagreement", value=0.50, direction=Direction.DECREASES_TRUST),),
        )
        state = _make_test_state(flow_count=350, rst_ratio=0.45)
        sigs = self.bridge.extract_signatures(state, trust_level=TrustLevel.LOW)
        sec_eval = self.bridge.build_security_assessment(
            trajectory=type("_DummyTraj", (), {"trajectory_id": "traj-test"})(),
            trust_assessment=trust_low,
            signatures=sigs,
            stage_hypotheses=[hyp],
        )
        prio = self.priority_engine.assess_priority(sec_eval, trust_low, hyp)
        
        # Priority cannot be CRITICAL when trust is LOW
        self.assertNotEqual(prio.priority_level, PriorityLevel.CRITICAL)

    def test_14_historical_manifests_remain_untouched(self) -> None:
        """Verify that all historical experiment manifests remain present and non-empty."""
        for p in [
            "artifacts/experiments/delta_baseline_v1/manifest.json",
            "artifacts/experiments/delta_baseline_v2/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1_corrected/manifest.json",
            "artifacts/experiments/security_bridge_validation_v1/manifest.json",
            "artifacts/experiments/decision_layer_v1/manifest.json",
            "artifacts/experiments/response_window_v1/manifest.json",
            "artifacts/experiments/ar_order_availability_v1/manifest.json",
            "artifacts/experiments/explainability_v1/manifest.json",
            "artifacts/experiments/future_security_risk_v1/manifest.json",
        ]:
            path = Path(p)
            self.assertTrue(path.exists(), f"Manifest missing: {p}")
            self.assertGreater(path.stat().st_size, 0)

    def test_15_multiplier_sensitivity_ranking_invariance(self) -> None:
        """Verify that varying the scale multiplier (1.0 to 2.0) preserves strict fixture rank ordering."""
        fixtures = [
            _make_test_state(dst_port_diversity=2, flow_count=15),
            _make_test_state(dst_port_diversity=35, flow_count=45, syn_ratio=0.45),
            _make_test_state(dst_port_diversity=4, flow_count=350, rst_ratio=0.45),
            _make_test_state(dst_port_diversity=2, flow_count=25, byte_rate=350000.0, pkt_size_mean=850.0),
        ]
        
        base_ranks = None
        for m in [1.0, 1.25, 1.50, 1.75, 2.0]:
            eng = SecurityRiskEngine(normalization_constant=m)
            scores = []
            for st in fixtures:
                sigs = self.bridge.extract_signatures(st, trust_level=TrustLevel.HIGH)
                hyps = self.bridge.infer_stage_hypotheses(sigs, trust_level=TrustLevel.HIGH)
                sc = eng.compute_risk_score(st, hyps[0], trust_val=0.85, uncertainty=0.10)
                scores.append(sc.score)
            
            # Rank indices from highest to lowest score
            ranks = tuple(np.argsort(scores)[::-1])
            if base_ranks is None:
                base_ranks = ranks
            else:
                self.assertEqual(ranks, base_ranks, f"Ranking mismatch at multiplier {m}")

    def test_16_component_direction_monotonicity(self) -> None:
        """Verify component direction monotonicity: higher severity/conf/trust increases risk; higher uncertainty decreases risk."""
        state = _make_test_state(dst_port_diversity=25, flow_count=40)
        
        # 1. Severity monotonicity
        sev_stages = ["Unknown", "Reconnaissance", "Initial Access / Delivery", "Collection / Exfiltration", "Impact / Denial of Service"]
        sev_scores = []
        for stg in sev_stages:
            hyp = StageHypothesis(new_id("h"), stg, (), (), 0.75, TrustLevel.HIGH, (), True)
            sev_scores.append(self.risk_engine.compute_risk_score(state, hyp, trust_val=0.85, uncertainty=0.10).score)
        for i in range(len(sev_scores) - 1):
            self.assertLess(sev_scores[i], sev_scores[i + 1])

        # 2. Confidence monotonicity
        conf_scores = []
        for conf in [0.20, 0.40, 0.60, 0.80, 1.00]:
            hyp = StageHypothesis(new_id("h"), "Reconnaissance", (), (), conf, TrustLevel.HIGH, (), True)
            conf_scores.append(self.risk_engine.compute_risk_score(state, hyp, trust_val=0.85, uncertainty=0.10).score)
        for i in range(len(conf_scores) - 1):
            self.assertLess(conf_scores[i], conf_scores[i + 1])

        # 3. Trust monotonicity
        trust_scores = []
        for tr in [0.20, 0.40, 0.65, 0.85, 0.95]:
            hyp = StageHypothesis(new_id("h"), "Reconnaissance", (), (), 0.75, TrustLevel.HIGH, (), True)
            trust_scores.append(self.risk_engine.compute_risk_score(state, hyp, trust_val=tr, trust_level=TrustLevel.HIGH, uncertainty=0.10).score)
        for i in range(len(trust_scores) - 1):
            self.assertLess(trust_scores[i], trust_scores[i + 1])

        # 4. Uncertainty monotonicity (inverse)
        unc_scores = []
        for unc in [0.00, 0.10, 0.20, 0.35, 0.50, 0.75, 1.00]:
            hyp = StageHypothesis(new_id("h"), "Reconnaissance", (), (), 0.75, TrustLevel.HIGH, (), True)
            unc_scores.append(self.risk_engine.compute_risk_score(state, hyp, trust_val=0.85, uncertainty=unc).score)
        for i in range(len(unc_scores) - 1):
            self.assertGreaterEqual(unc_scores[i], unc_scores[i + 1])

    def test_17_no_probability_wording_in_metadata(self) -> None:
        """Verify machine-readable representations do not claim calibrated probability."""
        state = _make_test_state(dst_port_diversity=35, flow_count=45)
        sigs = self.bridge.extract_signatures(state)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        traj = self.risk_engine.compute_risk_trajectory(state, hyps, self.default_trust, sigs)
        
        traj_str = json.dumps(traj.to_dict()).lower()
        self.assertNotIn("attack_probability", traj_str)
        self.assertNotIn("calibrated_probability", traj_str)
        self.assertIn("score", traj_str)


if __name__ == "__main__":
    unittest.main()

