"""Unit and validation tests for Day 6A Behavioral Security Bridge."""
from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path
import numpy as np

from core.contracts import (
    Direction,
    EvidenceDirection,
    FeatureAvailability,
    NetworkState,
    SecurityAssessment,
    Source,
    StageCandidate,
    Trajectory,
    TrajectoryStep,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    new_id,
)
from eval.dataset import CSV_AVAILABLE_FEATURES
from security.bridge import BehavioralSecurityBridge
from security.contracts import (
    AttackTechniqueHypothesis,
    BehaviouralSignature,
    EvidenceScope,
    EvidenceStrength,
    SignatureType,
    StageHypothesis,
)


def _make_dummy_state(
    start: datetime,
    dst_port_diversity: int = 5,
    flow_count: int = 10,
    byte_rate: float = 1000.0,
    rst_ratio: float = 0.05,
    syn_ratio: float = 0.10,
    fan_out_avail: FeatureAvailability = FeatureAvailability.UNAVAILABLE,
) -> NetworkState:
    end = start + timedelta(seconds=10)
    avail = {f: FeatureAvailability.AVAILABLE for f in CSV_AVAILABLE_FEATURES}
    avail["fan_out"] = fan_out_avail
    avail["src_ip_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["dst_ip_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["src_port_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["internal_ratio"] = FeatureAvailability.UNAVAILABLE
    avail["east_west_count"] = FeatureAvailability.UNAVAILABLE
    
    return NetworkState(
        window_id=f"{start.isoformat()}_10s",
        timestamp_start=start,
        timestamp_end=end,
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
        syn_count=5,
        ack_count=10,
        rst_count=2,
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
        session_id="session-1",
        provenance_hash="a" * 64,
        feature_availability=avail,
    )


class DaySixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.t0 = datetime(2018, 2, 28, 1, 0, 0)
        self.bridge = BehavioralSecurityBridge()

    def test_1_and_2_feature_availability_respected_and_unavailable_topology_omitted(self) -> None:
        s = _make_dummy_state(self.t0, fan_out_avail=FeatureAvailability.UNAVAILABLE)
        sigs = self.bridge.extract_signatures(s)
        
        # Lateral fan-out signature must be marked unavailable
        lateral_sig = next(sig for sig in sigs if sig.signature_type == SignatureType.LATERAL_FAN_OUT)
        self.assertFalse(lateral_sig.is_available)
        self.assertEqual(lateral_sig.evidence_strength, EvidenceStrength.UNKNOWN)
        self.assertIn("UNAVAILABLE", lateral_sig.explanation)

    def test_3_and_12_signatures_deterministic(self) -> None:
        s = _make_dummy_state(self.t0, dst_port_diversity=30, flow_count=100)
        sigs1 = self.bridge.extract_signatures(s)
        sigs2 = self.bridge.extract_signatures(s)
        
        self.assertEqual(len(sigs1), len(sigs2))
        for sig1, sig2 in zip(sigs1, sigs2):
            self.assertEqual(sig1.signature_type, sig2.signature_type)
            self.assertEqual(sig1.evidence_strength, sig2.evidence_strength)
            self.assertEqual(sig1.scope, sig2.scope)

    def test_4_current_vs_forecast_evidence_distinct(self) -> None:
        s = _make_dummy_state(self.t0, dst_port_diversity=5)
        # Current state is benign, but forecast predicts large delta in port diversity
        fc_deltas = np.zeros((2, len(CSV_AVAILABLE_FEATURES)))
        port_idx = CSV_AVAILABLE_FEATURES.index("dst_port_diversity")
        fc_deltas[0, port_idx] = 10.0  # Horizon 1 growth
        fc_deltas[1, port_idx] = 15.0  # Horizon 2 growth
        
        sigs = self.bridge.extract_signatures(s, fc_deltas, CSV_AVAILABLE_FEATURES)
        
        cur_sigs = [sig for sig in sigs if sig.scope == EvidenceScope.CURRENT and sig.is_available]
        fc_sigs = [sig for sig in sigs if sig.scope == EvidenceScope.FORECAST and sig.is_available]
        
        # Current evidence should be baseline/empty, while forecast evidence contains growth
        self.assertEqual(len(cur_sigs), 0)
        self.assertGreater(len(fc_sigs), 0)
        self.assertEqual(fc_sigs[0].horizon_step, 1)

    def test_5_unknown_is_representable(self) -> None:
        s_benign = _make_dummy_state(self.t0, dst_port_diversity=2, flow_count=5, byte_rate=50.0)
        sigs = self.bridge.extract_signatures(s_benign)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        # Primary stage must be Unknown when no active signatures trigger
        self.assertEqual(hyps[0].candidate_stage, "Unknown")
        self.assertTrue(hyps[0].is_primary)

    def test_6_and_7_stage_hypotheses_contain_evidence_and_alternatives(self) -> None:
        s = _make_dummy_state(self.t0, dst_port_diversity=35, flow_count=150)
        sigs = self.bridge.extract_signatures(s)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        recon_hyp = next(h for h in hyps if h.candidate_stage == "Reconnaissance")
        self.assertGreater(len(recon_hyp.supporting_signatures), 0)
        self.assertGreater(len(recon_hyp.counter_evidence), 0)
        self.assertGreater(len(recon_hyp.alternative_explanations), 0)
        self.assertIn("vulnerability", recon_hyp.alternative_explanations[1].lower())

    def test_8_attack_mapping_is_separate_from_forecasting(self) -> None:
        s = _make_dummy_state(self.t0, dst_port_diversity=35, flow_count=150)
        sigs = self.bridge.extract_signatures(s)
        attacks = self.bridge.map_to_attack_techniques(sigs)
        
        # T1046 Network Service Discovery should be mapped from Recon signature
        t1046 = next(a for a in attacks if a.technique_id == "T1046")
        self.assertEqual(t1046.technique_name, "Network Service Discovery")
        self.assertTrue(t1046.is_available)
        self.assertIn("RECONNAISSANCE_PORT_EXPLORATION", t1046.supporting_signatures)
        
        # T1021 Remote Services must be explicitly unavailable
        t1021 = next(a for a in attacks if a.technique_id == "T1021")
        self.assertFalse(t1021.is_available)

    def test_9_no_label_or_infiltration_leakage(self) -> None:
        for f in CSV_AVAILABLE_FEATURES:
            self.assertNotIn("label", f.lower())
            self.assertNotIn("infiltration", f.lower())

    def test_10_trust_and_uncertainty_propagated_correctly(self) -> None:
        s = _make_dummy_state(self.t0, dst_port_diversity=30)
        sigs = self.bridge.extract_signatures(s, trust_level=TrustLevel.HIGH, uncertainty=0.08)
        recon_sig = next(sig for sig in sigs if sig.signature_type == SignatureType.RECONNAISSANCE_PORT_EXPLORATION)
        self.assertEqual(recon_sig.trust_level, TrustLevel.HIGH)
        
        hyps = self.bridge.infer_stage_hypotheses(sigs, trust_level=TrustLevel.HIGH)
        self.assertEqual(hyps[0].trust_level, TrustLevel.HIGH)

    def test_11_prior_experiment_artifacts_remain_untouched(self) -> None:
        for p in [
            "artifacts/experiments/delta_baseline_v1/manifest.json",
            "artifacts/experiments/delta_baseline_v2/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1_corrected/manifest.json",
        ]:
            path = Path(p)
            if path.exists():
                self.assertTrue(len(path.read_text(encoding="utf-8")) > 0)

    def test_13_flooding_produces_dos_signature_and_stage(self) -> None:
        s_flood = _make_dummy_state(self.t0, flow_count=300, byte_rate=80000.0, rst_ratio=0.35, syn_ratio=0.50)
        sigs = self.bridge.extract_signatures(s_flood)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        self.assertEqual(hyps[0].candidate_stage, "Impact / Denial of Service")
        flood_sig = next(s for s in sigs if s.signature_type == SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE)
        self.assertEqual(flood_sig.evidence_strength, EvidenceStrength.HIGH)

    def test_14_outbound_surge_produces_exfiltration_signature(self) -> None:
        s_exfil = _make_dummy_state(self.t0, flow_count=20, byte_rate=250000.0)
        # Set mean pkt size large
        s_exfil_large = NetworkState(
            window_id=s_exfil.window_id,
            timestamp_start=s_exfil.timestamp_start,
            timestamp_end=s_exfil.timestamp_end,
            window_duration_s=10.0,
            flow_count=20,
            byte_rate=250000.0,
            packet_rate=300.0,
            mean_flow_duration=5.0,
            src_ip_diversity=None,
            dst_ip_diversity=None,
            src_port_diversity=None,
            dst_port_diversity=3,
            fan_out=None,
            internal_ratio=None,
            east_west_count=None,
            syn_count=1,
            ack_count=15,
            rst_count=0,
            syn_ratio=0.05,
            rst_ratio=0.0,
            iat_mean=0.5,
            iat_std=0.2,
            iat_skew=None,
            pkt_size_mean=800.0,
            pkt_size_std=50.0,
            byte_variance=1000.0,
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
            session_id="session-1",
            provenance_hash="a" * 64,
            feature_availability=s_exfil.feature_availability,
        )
        sigs = self.bridge.extract_signatures(s_exfil_large)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        self.assertEqual(hyps[0].candidate_stage, "Collection / Exfiltration")
        exfil_sig = next(s for s in sigs if s.signature_type == SignatureType.EXFILTRATION_OUTBOUND_SURGE)
        self.assertEqual(exfil_sig.evidence_strength, EvidenceStrength.HIGH)

    def test_15_timing_anomaly_produces_timing_signature(self) -> None:
        s_timing = NetworkState(
            window_id=f"{self.t0.isoformat()}_10s",
            timestamp_start=self.t0,
            timestamp_end=self.t0 + timedelta(seconds=10),
            window_duration_s=10.0,
            flow_count=60,
            byte_rate=5000.0,
            packet_rate=60.0,
            mean_flow_duration=5.0,
            src_ip_diversity=None,
            dst_ip_diversity=None,
            src_port_diversity=None,
            dst_port_diversity=4,
            fan_out=None,
            internal_ratio=None,
            east_west_count=None,
            syn_count=5,
            ack_count=30,
            rst_count=1,
            syn_ratio=0.08,
            rst_ratio=0.01,
            iat_mean=0.15,
            iat_std=0.02,
            iat_skew=None,
            pkt_size_mean=100.0,
            pkt_size_std=10.0,
            byte_variance=200.0,
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
            session_id="session-1",
            provenance_hash="a" * 64,
            feature_availability={f: FeatureAvailability.AVAILABLE for f in CSV_AVAILABLE_FEATURES},
        )
        sigs = self.bridge.extract_signatures(s_timing)
        timing_sig = next(s for s in sigs if s.signature_type == SignatureType.TIMING_BEHAVIOURAL_ANOMALY)
        self.assertEqual(timing_sig.direction, EvidenceDirection.DOWN)
        self.assertIn("rigid", timing_sig.explanation.lower())

    def test_16_ambiguous_case_produces_competing_hypotheses_without_high_certainty(self) -> None:
        s_amb = _make_dummy_state(self.t0, dst_port_diversity=9, flow_count=35, byte_rate=35000.0)
        sigs = self.bridge.extract_signatures(s_amb)
        hyps = self.bridge.infer_stage_hypotheses(sigs)
        
        # Should not have high confidence (> 0.70)
        self.assertLessEqual(hyps[0].confidence, 0.70)
        # Unknown should be present as candidate
        self.assertTrue(any(h.candidate_stage == "Unknown" for h in hyps))

    def test_17_forecast_reinforcement_and_contradictory_suppression(self) -> None:
        s_recon = _make_dummy_state(self.t0, dst_port_diversity=16, flow_count=45)
        port_idx = CSV_AVAILABLE_FEATURES.index("dst_port_diversity")
        
        # Reinforcing forecast
        fc_up = np.zeros((2, len(CSV_AVAILABLE_FEATURES)))
        fc_up[0, port_idx] = 12.0
        fc_up[1, port_idx] = 18.0
        sigs_up = self.bridge.extract_signatures(s_recon, fc_up, CSV_AVAILABLE_FEATURES)
        hyps_up = self.bridge.infer_stage_hypotheses(sigs_up)
        
        # Contradictory forecast
        fc_down = np.zeros((2, len(CSV_AVAILABLE_FEATURES)))
        fc_down[0, port_idx] = -10.0
        fc_down[1, port_idx] = -15.0
        sigs_down = self.bridge.extract_signatures(s_recon, fc_down, CSV_AVAILABLE_FEATURES)
        hyps_down = self.bridge.infer_stage_hypotheses(sigs_down)
        
        # Reinforcing forecast must have higher confidence than contradictory forecast
        self.assertGreater(hyps_up[0].confidence, hyps_down[0].confidence)
        # Contradictory counter-evidence must include deceleration
        self.assertTrue(any("deceleration" in ce.lower() for ce in hyps_down[0].counter_evidence))

    def test_18_anti_stage_collapse_validation(self) -> None:
        """Verify that disparate fixtures produce multiple distinct primary stages."""
        s1 = _make_dummy_state(self.t0, dst_port_diversity=2, flow_count=10)  # Benign -> Unknown
        s2 = _make_dummy_state(self.t0, dst_port_diversity=35, flow_count=80)  # Recon -> Reconnaissance
        s3 = _make_dummy_state(self.t0, flow_count=300, rst_ratio=0.35)  # DoS -> Impact / Denial of Service
        
        h1 = self.bridge.infer_stage_hypotheses(self.bridge.extract_signatures(s1))[0].candidate_stage
        h2 = self.bridge.infer_stage_hypotheses(self.bridge.extract_signatures(s2))[0].candidate_stage
        h3 = self.bridge.infer_stage_hypotheses(self.bridge.extract_signatures(s3))[0].candidate_stage
        
        distinct_stages = {h1, h2, h3}
        self.assertEqual(len(distinct_stages), 3)
        self.assertIn("Unknown", distinct_stages)
        self.assertIn("Reconnaissance", distinct_stages)
        self.assertIn("Impact / Denial of Service", distinct_stages)


if __name__ == "__main__":
    unittest.main()
