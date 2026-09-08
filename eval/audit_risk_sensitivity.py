"""
Audit script for Future Security-Risk Score Robustness (SIH 26153).
Runs non-modifying sensitivity checks across:
- Multipliers: 1.0, 1.25, 1.50, 1.75, 2.0
- Component directions (monotonicity)
- Contradiction scenarios
- Score distributions across fixtures & telemetry streams
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
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
from eval.dataset import CSV_AVAILABLE_FEATURES, load_states_from_jsonl, OBSERVED_INFILTRATION_BLOCKS
from security.bridge import BehavioralSecurityBridge
from security.risk_engine import SecurityRiskEngine, STAGE_SEVERITY_WEIGHTS
from security.contracts import StageHypothesis, SignatureType, EvidenceStrength, EvidenceDirection


def _create_synthetic_fixture_state(
    name: str,
    flow_count: int,
    byte_rate: float,
    packet_rate: float,
    dst_port_diversity: int,
    syn_ratio: float = 0.05,
    rst_ratio: float = 0.05,
    iat_mean: float = 2.0,
    iat_std: float = 1.5,
    pkt_size_mean: float = 100.0,
    fan_out_avail: FeatureAvailability = FeatureAvailability.UNAVAILABLE,
) -> NetworkState:
    start = datetime(2018, 3, 1, 12, 0, 0)
    end = start + timedelta(seconds=10)
    avail = {f: FeatureAvailability.AVAILABLE for f in CSV_AVAILABLE_FEATURES}
    avail["fan_out"] = fan_out_avail
    avail["src_ip_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["dst_ip_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["src_port_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["internal_ratio"] = FeatureAvailability.UNAVAILABLE
    avail["east_west_count"] = FeatureAvailability.UNAVAILABLE
    return NetworkState(
        window_id=f"fixture_{name}_10s",
        timestamp_start=start,
        timestamp_end=end,
        window_duration_s=10.0,
        flow_count=flow_count,
        byte_rate=byte_rate,
        packet_rate=packet_rate,
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
        iat_mean=iat_mean,
        iat_std=iat_std,
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
        session_id="session-fixture",
        provenance_hash="f" * 64,
        feature_availability=avail,
    )


def audit() -> None:
    bridge = BehavioralSecurityBridge()
    fixtures = {
        "1_benign_baseline": _create_synthetic_fixture_state(
            "benign_baseline", flow_count=15, byte_rate=1200.0, packet_rate=20.0, dst_port_diversity=2
        ),
        "2_port_exploration": _create_synthetic_fixture_state(
            "port_exploration", flow_count=45, byte_rate=4000.0, packet_rate=60.0, dst_port_diversity=35, syn_ratio=0.45
        ),
        "3_connection_flooding": _create_synthetic_fixture_state(
            "connection_flooding", flow_count=350, byte_rate=25000.0, packet_rate=450.0, dst_port_diversity=4, rst_ratio=0.45
        ),
        "4_sustained_outbound_surge": _create_synthetic_fixture_state(
            "sustained_outbound_surge", flow_count=25, byte_rate=350000.0, packet_rate=300.0, dst_port_diversity=2, pkt_size_mean=850.0
        ),
        "5_timing_anomaly": _create_synthetic_fixture_state(
            "timing_anomaly", flow_count=60, byte_rate=5000.0, packet_rate=80.0, dst_port_diversity=3, iat_mean=0.25, iat_std=0.02
        ),
        "6_ambiguous_mixed": _create_synthetic_fixture_state(
            "ambiguous_mixed", flow_count=35, byte_rate=8000.0, packet_rate=50.0, dst_port_diversity=12, syn_ratio=0.18
        ),
    }

    dummy_trust = TrustAssessment(
        assessment_id=new_id("trust-fix"),
        forecast_id="fc-fix",
        forecast_confidence=0.85,
        model_disagreement=0.05,
        distribution_shift_score=0.05,
        novelty_score=0.05,
        historical_error=0.10,
        data_quality=1.0,
        composite_trust=0.85,
        trust_level=TrustLevel.HIGH,
        contributing_factors=(TrustFactor(name="baseline", value=0.85, direction=Direction.INCREASES_TRUST),),
    )

    # -------------------------------------------------------------------------
    # PART A: Multiplier Sensitivity
    # -------------------------------------------------------------------------
    print("=== PART A: MULTIPLIER SENSITIVITY ===")
    multipliers = [1.0, 1.25, 1.50, 1.75, 2.0]
    
    for m in multipliers:
        eng = SecurityRiskEngine(normalization_constant=m)
        print(f"\n--- Multiplier = {m:.2f} ---")
        scores = {}
        clipping_count = 0
        for name, st in fixtures.items():
            sigs = bridge.extract_signatures(st, trust_level=TrustLevel.HIGH, uncertainty=0.10)
            hyps = bridge.infer_stage_hypotheses(sigs, trust_level=TrustLevel.HIGH)
            traj = eng.compute_risk_trajectory(st, hyps, dummy_trust, sigs)
            r0 = traj.current_risk.score
            scores[name] = r0
            if r0 >= 1.0:
                clipping_count += 1
            print(f"  {name:<30}: R0={r0:.4f} | R1(+10s)={traj.future_risks[0].score:.4f} | R2(+20s)={traj.future_risks[1].score:.4f} | R3(+30s)={traj.future_risks[2].score:.4f}")
        
        # Rankings
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        print(f"  Rank Ordering: {' > '.join([k.split('_')[1] for k, v in ranked])}")
        print(f"  Range: [{min(scores.values()):.4f}, {max(scores.values()):.4f}] | Spread: {max(scores.values()) - min(scores.values()):.4f}")
        print(f"  Benign vs Recon Separation: {scores['2_port_exploration'] - scores['1_benign_baseline']:.4f}")
        print(f"  Benign vs Flooding Separation: {scores['3_connection_flooding'] - scores['1_benign_baseline']:.4f}")
        print(f"  Clipping count at 1.0: {clipping_count}")

    # -------------------------------------------------------------------------
    # PART B: Component Sensitivity (Monotonicity)
    # -------------------------------------------------------------------------
    print("\n=== PART B: COMPONENT SENSITIVITY (MONOTONICITY) ===")
    eng = SecurityRiskEngine(normalization_constant=1.50)
    base_state = fixtures["2_port_exploration"]
    
    # 1. Severity effect
    print("\n1. Effect of Severity (holding Conf=0.75, Trust=0.85, Unc=0.10):")
    for stg, sev in STAGE_SEVERITY_WEIGHTS.items():
        hyp = StageHypothesis(new_id("h"), stg, (), (), 0.75, TrustLevel.HIGH, (), True)
        sc = eng.compute_risk_score(base_state, hyp, trust_val=0.85, uncertainty=0.10)
        print(f"  Stage={stg:<30} (Severity={sev:.2f}) -> Score={sc.score:.4f}")

    # 2. Stage Confidence effect
    print("\n2. Effect of Stage Confidence (Recon, Severity=0.40, Trust=0.85, Unc=0.10):")
    for conf in [0.20, 0.40, 0.60, 0.80, 1.00]:
        hyp = StageHypothesis(new_id("h"), "Reconnaissance", (), (), conf, TrustLevel.HIGH, (), True)
        sc = eng.compute_risk_score(base_state, hyp, trust_val=0.85, uncertainty=0.10)
        print(f"  Confidence={conf:.2f} -> Score={sc.score:.4f}")

    # 3. Trust effect
    print("\n3. Effect of Trust (Recon, Severity=0.40, Conf=0.75, Unc=0.10):")
    for tr, lvl in [(0.20, TrustLevel.LOW), (0.40, TrustLevel.LOW), (0.65, TrustLevel.MEDIUM), (0.85, TrustLevel.HIGH), (0.95, TrustLevel.HIGH)]:
        hyp = StageHypothesis(new_id("h"), "Reconnaissance", (), (), 0.75, lvl, (), True)
        sc = eng.compute_risk_score(base_state, hyp, trust_val=tr, trust_level=lvl, uncertainty=0.10)
        print(f"  Trust={tr:.2f} ({lvl.value:<12}) -> Score={sc.score:.4f}")

    # 4. Uncertainty effect
    print("\n4. Effect of Uncertainty (Recon, Severity=0.40, Conf=0.75, Trust=0.85):")
    for unc in [0.00, 0.10, 0.20, 0.35, 0.50, 0.75, 1.00]:
        hyp = StageHypothesis(new_id("h"), "Reconnaissance", (), (), 0.75, TrustLevel.HIGH, (), True)
        sc = eng.compute_risk_score(base_state, hyp, trust_val=0.85, uncertainty=unc)
        print(f"  Uncertainty={unc:.2f} -> Score={sc.score:.4f}")

    # -------------------------------------------------------------------------
    # PART C: Contradiction Robustness
    # -------------------------------------------------------------------------
    print("\n=== PART C: CONTRADICTION ROBUSTNESS ===")
    recon_state = fixtures["2_port_exploration"]
    
    # Reinforcing
    reinf_deltas = np.zeros((3, len(CSV_AVAILABLE_FEATURES)))
    p_idx = CSV_AVAILABLE_FEATURES.index("dst_port_diversity")
    reinf_deltas[:, p_idx] = [8.0, 10.0, 12.0]
    sigs_reinf = bridge.extract_signatures(recon_state, reinf_deltas, CSV_AVAILABLE_FEATURES, TrustLevel.HIGH)
    hyps_reinf = bridge.infer_stage_hypotheses(sigs_reinf, TrustLevel.HIGH)
    traj_reinf = eng.compute_risk_trajectory(recon_state, hyps_reinf, dummy_trust, sigs_reinf)

    # Contradictory
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
    sigs_contra = bridge.extract_signatures(recon_state, contra_deltas, CSV_AVAILABLE_FEATURES, TrustLevel.LOW)
    hyps_contra = bridge.infer_stage_hypotheses(sigs_contra, TrustLevel.LOW)
    traj_contra = eng.compute_risk_trajectory(recon_state, hyps_contra, trust_contra, sigs_contra)

    print(f"Reinforcing Recon:   NOW={traj_reinf.current_risk.score:.4f} | +10s={traj_reinf.future_risks[0].score:.4f} | +20s={traj_reinf.future_risks[1].score:.4f} | +30s={traj_reinf.future_risks[2].score:.4f}")
    print(f"Contradictory Recon: NOW={traj_contra.current_risk.score:.4f} | +10s={traj_contra.future_risks[0].score:.4f} | +20s={traj_contra.future_risks[1].score:.4f} | +30s={traj_contra.future_risks[2].score:.4f}")
    print(f"Suppression delta at +10s: {traj_reinf.future_risks[0].score - traj_contra.future_risks[0].score:.4f}")

    # -------------------------------------------------------------------------
    # PART D: Score Distribution
    # -------------------------------------------------------------------------
    print("\n=== PART D: SCORE DISTRIBUTION ===")
    fix_scores = {}
    for name, st in fixtures.items():
        sigs = bridge.extract_signatures(st, trust_level=TrustLevel.HIGH, uncertainty=0.10)
        hyps = bridge.infer_stage_hypotheses(sigs, trust_level=TrustLevel.HIGH)
        traj = eng.compute_risk_trajectory(st, hyps, dummy_trust, sigs)
        scores = [traj.current_risk.score] + [fr.score for fr in traj.future_risks]
        fix_scores[name] = scores
        print(f"  {name:<30}: Min={min(scores):.4f}, Max={max(scores):.4f}, Mean={np.mean(scores):.4f}, Median={np.median(scores):.4f}")


if __name__ == "__main__":
    audit()
