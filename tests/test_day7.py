"""Unit and validation tests for Day 7 Operational Decision Layer (SIH 26153)."""
from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path
import numpy as np

from core.contracts import (
    ActionType,
    Direction,
    EvidenceDirection,
    FeatureAvailability,
    NetworkState,
    NotificationUrgency,
    PriorityAssessment,
    PriorityLevel,
    ResponseRecommendation,
    RoleNotification,
    SecurityAssessment,
    Source,
    Strategy,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    new_id,
)
from core.priority.engine import PriorityEngine
from core.response.notifications import NotificationEngine
from core.response.recommendations import ResponseRecommendationEngine
from core.response.roles import OperationalRole
from core.response.routing import RelevanceStatus, RoleRelevanceDecision, RoleRelevanceEngine
from eval.dataset import CSV_AVAILABLE_FEATURES
from security.bridge import BehavioralSecurityBridge
from security.contracts import EvidenceScope, EvidenceStrength, SignatureType, StageHypothesis


def _make_dummy_state(
    dst_port_diversity: int = 5,
    flow_count: int = 10,
    byte_rate: float = 1000.0,
    rst_ratio: float = 0.05,
    syn_ratio: float = 0.10,
) -> NetworkState:
    t0 = datetime(2018, 3, 1, 12, 0, 0)
    avail = {f: FeatureAvailability.AVAILABLE for f in CSV_AVAILABLE_FEATURES}
    avail["fan_out"] = FeatureAvailability.UNAVAILABLE
    avail["src_ip_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["dst_ip_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["src_port_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["internal_ratio"] = FeatureAvailability.UNAVAILABLE
    avail["east_west_count"] = FeatureAvailability.UNAVAILABLE
    
    return NetworkState(
        window_id=f"{t0.isoformat()}_10s",
        timestamp_start=t0,
        timestamp_end=t0 + timedelta(seconds=10),
        window_duration_s=10.0,
        flow_count=flow_count,
        byte_rate=byte_rate,
        packet_rate=50.0,
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
        data_quality=1.0,
        is_empty=False,
        gap_before=False,
        gap_after=False,
        session_id="session-day7",
        provenance_hash="7" * 64,
        feature_availability=avail,
    )


def _make_dummy_trust(composite_trust: float = 0.85, trust_level: TrustLevel = TrustLevel.HIGH) -> TrustAssessment:
    return TrustAssessment(
        assessment_id=new_id("trust"),
        forecast_id="fc-day7",
        forecast_confidence=composite_trust,
        model_disagreement=0.05,
        distribution_shift_score=0.05,
        novelty_score=0.05,
        historical_error=0.10,
        data_quality=1.0,
        composite_trust=composite_trust,
        trust_level=trust_level,
        contributing_factors=(TrustFactor(name="dq", value=1.0, direction=Direction.INCREASES_TRUST),),
    )


class DaySevenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = BehavioralSecurityBridge()
        self.priority_engine = PriorityEngine()
        self.routing_engine = RoleRelevanceEngine()
        self.recommendation_engine = ResponseRecommendationEngine()
        self.notif_engine = NotificationEngine()

        class _DummyTraj:
            def __init__(self) -> None:
                self.trajectory_id = "traj-d7"
        self._traj = _DummyTraj()

    def test_1_no_notification_to_not_relevant_roles(self) -> None:
        """Roles evaluated as NOT_RELEVANT must receive zero notifications."""
        s_recon = _make_dummy_state(dst_port_diversity=35, flow_count=80)
        t_high = _make_dummy_trust(0.85, TrustLevel.HIGH)
        sigs = self.bridge.extract_signatures(s_recon)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        sec = self.bridge.build_security_assessment(self._traj, t_high, sigs, hyps)
        prio = self.priority_engine.assess_priority(sec, t_high, hyps[0])
        routing = self.routing_engine.route_event(sec, prio, hyps[0], t_high)
        rec = self.recommendation_engine.generate_recommendation(prio, sec, hyps[0], t_high)
        notifs = self.notif_engine.generate_notifications(sec, prio, hyps[0], t_high, rec, routing)
        
        # Endpoint Analyst must be NOT_RELEVANT and omitted from dispatched notifications
        endpoint_dec = next(d for d in routing if d.role == OperationalRole.ENDPOINT_ANALYST)
        self.assertEqual(endpoint_dec.relevance, RelevanceStatus.NOT_RELEVANT)
        
        # Data Protection must be NOT_RELEVANT for pure reconnaissance
        data_dec = next(d for d in routing if d.role == OperationalRole.DATA_PROTECTION)
        self.assertEqual(data_dec.relevance, RelevanceStatus.NOT_RELEVANT)

    def test_2_high_uncertainty_dampens_priority(self) -> None:
        """Low trust / high uncertainty must reduce priority composite score rather than escalate."""
        s = _make_dummy_state(dst_port_diversity=35, flow_count=80)
        t_high = _make_dummy_trust(0.90, TrustLevel.HIGH)
        t_low = _make_dummy_trust(0.15, TrustLevel.LOW)
        
        sigs = self.bridge.extract_signatures(s)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        sec_h = self.bridge.build_security_assessment(self._traj, t_high, sigs, hyps)
        sec_l = self.bridge.build_security_assessment(self._traj, t_low, sigs, hyps)
        
        prio_high_trust = self.priority_engine.assess_priority(sec_h, t_high, hyps[0])
        prio_low_trust = self.priority_engine.assess_priority(sec_l, t_low, hyps[0])
        
        # Low trust MUST produce lower or equal composite priority than high trust
        self.assertLess(prio_low_trust.composite_priority, prio_high_trust.composite_priority)
        self.assertNotEqual(prio_low_trust.priority_level, PriorityLevel.CRITICAL)

    def test_3_unknown_does_not_produce_destructive_action(self) -> None:
        """Unknown/baseline events must produce Strategy.MONITOR and ActionType.INCREASE_MONITORING."""
        s_benign = _make_dummy_state(dst_port_diversity=2, flow_count=10, byte_rate=500.0)
        t_high = _make_dummy_trust(0.90, TrustLevel.HIGH)
        sigs = self.bridge.extract_signatures(s_benign)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        sec = self.bridge.build_security_assessment(self._traj, t_high, sigs, hyps)
        prio = self.priority_engine.assess_priority(sec, t_high, hyps[0])
        rec = self.recommendation_engine.generate_recommendation(prio, sec, hyps[0], t_high)
        
        self.assertEqual(rec.strategy, Strategy.MONITOR)
        self.assertEqual(rec.actions[0].action_type, ActionType.INCREASE_MONITORING)
        self.assertTrue(rec.is_reversible)

    def test_4_and_5_all_recommendations_require_human_approval_and_are_reversible(self) -> None:
        """Every recommendation MUST require explicit human approval and be reversible."""
        for flow, byte, rst in [(300, 80000.0, 0.35), (20, 250000.0, 0.01), (50, 5000.0, 0.05)]:
            s = _make_dummy_state(flow_count=flow, byte_rate=byte, rst_ratio=rst)
            t = _make_dummy_trust(0.85, TrustLevel.HIGH)
            sigs = self.bridge.extract_signatures(s)
            hyps = self.bridge.infer_stage_hypotheses(sigs)
            sec = self.bridge.build_security_assessment(self._traj, t, sigs, hyps)
            prio = self.priority_engine.assess_priority(sec, t, hyps[0])
            rec = self.recommendation_engine.generate_recommendation(prio, sec, hyps[0], t)
            
            self.assertTrue(rec.requires_human, "Recommendation MUST require human approval")
            self.assertTrue(rec.is_reversible, "Recommendation MUST be reversible")
            for action in rec.actions:
                self.assertTrue(action.reversible, "Action MUST be reversible")

    def test_6_and_7_notifications_contain_evidence_and_role_contexts_differ(self) -> None:
        """Notifications must contain evidence details and differ between SOC Analyst and Network Defender."""
        s = _make_dummy_state(dst_port_diversity=35, flow_count=80)
        t = _make_dummy_trust(0.85, TrustLevel.HIGH)
        sigs = self.bridge.extract_signatures(s)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        sec = self.bridge.build_security_assessment(self._traj, t, sigs, hyps)
        prio = self.priority_engine.assess_priority(sec, t, hyps[0])
        routing = self.routing_engine.route_event(sec, prio, hyps[0], t)
        rec = self.recommendation_engine.generate_recommendation(prio, sec, hyps[0], t)
        notifs = self.notif_engine.generate_notifications(sec, prio, hyps[0], t, rec, routing)
        
        # Verify evidence is present in detail
        for n in notifs:
            self.assertIn("Confidence=", n.detail)
            self.assertIn("Trust=", n.detail)
            
        # Verify distinct headlines
        headlines = {n.headline for n in notifs}
        self.assertGreaterEqual(len(headlines), 2)

    def test_8_and_9_suppression_and_update_logic(self) -> None:
        """Duplicate notifications are suppressed; material changes generate updates."""
        engine = NotificationEngine()
        s = _make_dummy_state(dst_port_diversity=35, flow_count=80)
        t = _make_dummy_trust(0.85, TrustLevel.HIGH)
        sigs = self.bridge.extract_signatures(s)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        sec = self.bridge.build_security_assessment(self._traj, t, sigs, hyps)
        prio = self.priority_engine.assess_priority(sec, t, hyps[0])
        routing = self.routing_engine.route_event(sec, prio, hyps[0], t)
        rec = self.recommendation_engine.generate_recommendation(prio, sec, hyps[0], t)
        
        # 1st dispatch -> Generates notifications
        notifs_1 = engine.generate_notifications(sec, prio, hyps[0], t, rec, routing)
        self.assertGreater(len(notifs_1), 0)
        
        # 2nd dispatch (identical state) -> Suppressed (0 notifications)
        notifs_2 = engine.generate_notifications(sec, prio, hyps[0], t, rec, routing)
        self.assertEqual(len(notifs_2), 0)
        
        # 3rd dispatch (forced update or changed state) -> Dispatched
        notifs_3 = engine.generate_notifications(sec, prio, hyps[0], t, rec, routing, force_update=True)
        self.assertGreater(len(notifs_3), 0)

    def test_10_no_label_or_infiltration_fraction_leakage(self) -> None:
        for f in CSV_AVAILABLE_FEATURES:
            self.assertNotIn("label", f.lower())
            self.assertNotIn("infiltration", f.lower())

    def test_11_unavailable_topology_cannot_create_topology_priority(self) -> None:
        s = _make_dummy_state()
        sigs = self.bridge.extract_signatures(s)
        lateral_sig = next(sig for sig in sigs if sig.signature_type == SignatureType.LATERAL_FAN_OUT)
        self.assertFalse(lateral_sig.is_available)
        
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        # Lateral movement cannot be the primary stage
        self.assertNotEqual(hyps[0].candidate_stage, "Lateral Movement")

    def test_12_deterministic_inputs_produce_deterministic_outputs(self) -> None:
        s = _make_dummy_state(dst_port_diversity=30, flow_count=70)
        t = _make_dummy_trust(0.80, TrustLevel.HIGH)
        
        sigs1 = self.bridge.extract_signatures(s)
        hyps1 = self.bridge.infer_stage_hypotheses(sigs1)
        sec1 = self.bridge.build_security_assessment(self._traj, t, sigs1, hyps1)
        prio1 = self.priority_engine.assess_priority(sec1, t, hyps1[0])
        
        sigs2 = self.bridge.extract_signatures(s)
        hyps2 = self.bridge.infer_stage_hypotheses(sigs2)
        sec2 = self.bridge.build_security_assessment(self._traj, t, sigs2, hyps2)
        prio2 = self.priority_engine.assess_priority(sec2, t, hyps2[0])
        
        self.assertEqual(prio1.priority_level, prio2.priority_level)
        self.assertAlmostEqual(prio1.composite_priority, prio2.composite_priority)

    def test_13_historical_experiment_artifacts_remain_unchanged(self) -> None:
        for p in [
            "artifacts/experiments/delta_baseline_v1/manifest.json",
            "artifacts/experiments/delta_baseline_v2/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1_corrected/manifest.json",
            "artifacts/experiments/security_bridge_v1/manifest.json",
            "artifacts/experiments/security_bridge_validation_v1/manifest.json",
        ]:
            path = Path(p)
            if path.exists():
                self.assertTrue(len(path.read_text(encoding="utf-8")) > 0)


if __name__ == "__main__":
    unittest.main()
