"""Behavioral Security Bridge Engine (SIH 26153).

Translates current network states and multi-step forecasted state evolution
into explainable, uncertainty-aware Behavioral Security Signatures, Stage Hypotheses,
and candidate MITRE ATT&CK technique mappings.
"""
from __future__ import annotations

from datetime import datetime
from typing import Mapping, Sequence

import numpy as np

from core.contracts import (
    EvidenceDirection,
    EvidenceItem,
    FeatureAvailability,
    NetworkState,
    SecurityAssessment,
    StageCandidate,
    Trajectory,
    TrustAssessment,
    TrustLevel,
    new_id,
)
from eval.metrics_v2 import RobustScaleStatistics
from security.contracts import (
    AttackTechniqueHypothesis,
    BehaviouralSignature,
    EvidenceScope,
    EvidenceStrength,
    FutureSecurityRiskScore,
    SecurityRiskTrajectory,
    SignatureType,
    StageHypothesis,
)
from security.risk_engine import SecurityRiskEngine



class BehavioralSecurityBridge:
    """
    Translates state telemetry and forecast trajectories into explainable
    security behavioural signatures and stage hypotheses.
    """
    def __init__(self, scales: RobustScaleStatistics | None = None) -> None:
        self.scales = scales
        
    def extract_signatures(
        self,
        current_state: NetworkState,
        forecast_deltas: np.ndarray | None = None,  # Shape: (H, n_features)
        feature_names: Sequence[str] | None = None,
        trust_level: TrustLevel = TrustLevel.MEDIUM,
        uncertainty: float = 0.20,
    ) -> list[BehaviouralSignature]:
        """
        Extract deterministic behavioural signatures from current telemetry and forecasted deltas.
        Distinguishes CURRENT evidence from FORECAST evidence.
        """
        signatures: list[BehaviouralSignature] = []
        c_vals = current_state.feature_values()
        cur_time = current_state.timestamp_end
        
        # 1. Reconnaissance / Port Exploration Signature
        dst_ports = c_vals.get("dst_port_diversity", 0.0)
        flows = c_vals.get("flow_count", 0.0)
        syn_ratio = c_vals.get("syn_ratio", 0.0)
        
        # Current evidence
        if dst_ports >= 15.0 or (dst_ports >= 8.0 and flows >= 30.0):
            strength = EvidenceStrength.HIGH if (dst_ports >= 25.0 or syn_ratio >= 0.30) else EvidenceStrength.MEDIUM
            signatures.append(
                BehaviouralSignature(
                    signature_id=new_id("sig-recon-cur"),
                    signature_type=SignatureType.RECONNAISSANCE_PORT_EXPLORATION,
                    scope=EvidenceScope.CURRENT,
                    horizon_step=0,
                    timestamp=cur_time,
                    current_values={"dst_port_diversity": dst_ports, "flow_count": flows, "syn_ratio": syn_ratio},
                    predicted_deltas={},
                    direction=EvidenceDirection.UP,
                    supporting_features=("dst_port_diversity", "flow_count", "syn_ratio"),
                    evidence_strength=strength,
                    uncertainty=0.10,
                    trust_level=trust_level,
                    explanation=f"Current destination port diversity is elevated ({dst_ports:.1f} ports across {flows:.0f} flows) with SYN ratio {syn_ratio:.2f}.",
                    alternative_explanations=(
                        "Legitimate microservice discovery / API probing",
                        "Administrative vulnerability scanning / asset inventory",
                        "Multi-tenant load balancer health monitoring",
                    ),
                    is_available=True,
                )
            )
            
        # Forecasted reconnaissance evolution
        if forecast_deltas is not None and feature_names is not None:
            f_list = list(feature_names)
            if "dst_port_diversity" in f_list:
                port_idx = f_list.index("dst_port_diversity")
                for h in range(forecast_deltas.shape[0]):
                    d_port = float(forecast_deltas[h, port_idx])
                    if d_port >= 3.0:
                        signatures.append(
                            BehaviouralSignature(
                                signature_id=new_id(f"sig-recon-fc-h{h+1}"),
                                signature_type=SignatureType.RECONNAISSANCE_PORT_EXPLORATION,
                                scope=EvidenceScope.FORECAST,
                                horizon_step=h + 1,
                                timestamp=cur_time,
                                current_values={"dst_port_diversity": dst_ports},
                                predicted_deltas={"dst_port_diversity_delta": d_port},
                                direction=EvidenceDirection.UP,
                                supporting_features=("dst_port_diversity",),
                                evidence_strength=EvidenceStrength.HIGH if d_port >= 8.0 else EvidenceStrength.MEDIUM,
                                uncertainty=uncertainty * (h + 1),
                                trust_level=trust_level,
                                explanation=f"Forecast h={h+1} predicts continued port exploration growth (Δ +{d_port:.1f} ports).",
                                alternative_explanations=(
                                    "Expanding legitimate service discovery sweep",
                                    "Multi-endpoint cluster health check cycle",
                                ),
                                is_available=True,
                            )
                        )
                    elif d_port <= -5.0 and dst_ports >= 15.0:
                        # Contradictory forecast: current elevated but forecast dropping sharply
                        signatures.append(
                            BehaviouralSignature(
                                signature_id=new_id(f"sig-recon-fc-dec-h{h+1}"),
                                signature_type=SignatureType.RECONNAISSANCE_PORT_EXPLORATION,
                                scope=EvidenceScope.FORECAST,
                                horizon_step=h + 1,
                                timestamp=cur_time,
                                current_values={"dst_port_diversity": dst_ports},
                                predicted_deltas={"dst_port_diversity_delta": d_port},
                                direction=EvidenceDirection.DOWN,
                                supporting_features=("dst_port_diversity",),
                                evidence_strength=EvidenceStrength.LOW,
                                uncertainty=uncertainty * (h + 1),
                                trust_level=trust_level,
                                explanation=f"Forecast h={h+1} predicts sharp deceleration/collapse in port exploration (Δ {d_port:.1f} ports).",
                                alternative_explanations=("Transient momentary probe completed / mean-reverting to baseline",),
                                is_available=True,
                            )
                        )

        # 2. Connection Flooding / Resource Pressure Signature
        rst_ratio = c_vals.get("rst_ratio", 0.0)
        pkt_rate = c_vals.get("packet_rate", 0.0)
        
        if (flows >= 80.0 and rst_ratio >= 0.15) or (flows >= 120.0 and syn_ratio >= 0.40) or (flows >= 200.0):
            strength = EvidenceStrength.HIGH if (rst_ratio >= 0.30 or flows >= 200.0) else EvidenceStrength.MEDIUM
            signatures.append(
                BehaviouralSignature(
                    signature_id=new_id("sig-flood-cur"),
                    signature_type=SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE,
                    scope=EvidenceScope.CURRENT,
                    horizon_step=0,
                    timestamp=cur_time,
                    current_values={"flow_count": flows, "rst_ratio": rst_ratio, "packet_rate": pkt_rate},
                    predicted_deltas={},
                    direction=EvidenceDirection.UP,
                    supporting_features=("flow_count", "rst_ratio", "packet_rate"),
                    evidence_strength=strength,
                    uncertainty=0.10,
                    trust_level=trust_level,
                    explanation=f"High connection volume ({flows:.0f} flows, {pkt_rate:.1f} pkts/s) with elevated connection reset/rejection ratio ({rst_ratio:.2f}).",
                    alternative_explanations=(
                        "Legitimate flash crowd / surge in client traffic",
                        "Misconfigured client retry loop against failing service",
                        "Upstream firewall / gateway TCP session table exhaustion",
                    ),
                    is_available=True,
                )
            )
            
        if forecast_deltas is not None and feature_names is not None:
            f_list = list(feature_names)
            if "flow_count" in f_list:
                flow_idx = f_list.index("flow_count")
                for h in range(forecast_deltas.shape[0]):
                    d_flow = float(forecast_deltas[h, flow_idx])
                    if d_flow >= 50.0:
                        signatures.append(
                            BehaviouralSignature(
                                signature_id=new_id(f"sig-flood-fc-h{h+1}"),
                                signature_type=SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE,
                                scope=EvidenceScope.FORECAST,
                                horizon_step=h + 1,
                                timestamp=cur_time,
                                current_values={"flow_count": flows},
                                predicted_deltas={"flow_count_delta": d_flow},
                                direction=EvidenceDirection.UP,
                                supporting_features=("flow_count",),
                                evidence_strength=EvidenceStrength.HIGH if d_flow >= 100.0 else EvidenceStrength.MEDIUM,
                                uncertainty=uncertainty * (h + 1),
                                trust_level=trust_level,
                                explanation=f"Forecast h={h+1} predicts rapid connection flooding growth (Δ +{d_flow:.0f} flows).",
                                alternative_explanations=("Anticipated surge in user traffic",),
                                is_available=True,
                            )
                        )

        # 3. Exfiltration-like Outbound Surge Signature
        byte_rate = c_vals.get("byte_rate", 0.0)
        pkt_size_mean = c_vals.get("pkt_size_mean", 0.0)
        
        if byte_rate >= 50000.0 and pkt_size_mean >= 300.0:
            strength = EvidenceStrength.HIGH if byte_rate >= 150000.0 else EvidenceStrength.MEDIUM
            signatures.append(
                BehaviouralSignature(
                    signature_id=new_id("sig-exfil-cur"),
                    signature_type=SignatureType.EXFILTRATION_OUTBOUND_SURGE,
                    scope=EvidenceScope.CURRENT,
                    horizon_step=0,
                    timestamp=cur_time,
                    current_values={"byte_rate": byte_rate, "pkt_size_mean": pkt_size_mean},
                    predicted_deltas={},
                    direction=EvidenceDirection.UP,
                    supporting_features=("byte_rate", "pkt_size_mean"),
                    evidence_strength=strength,
                    uncertainty=0.15,
                    trust_level=trust_level,
                    explanation=f"Sustained heavy data rate transfer ({byte_rate:,.0f} B/s) with large mean packet payload ({pkt_size_mean:.1f} bytes).",
                    alternative_explanations=(
                        "Scheduled database replication / cloud snapshot backup",
                        "Operating system / container image update synchronization",
                        "High-volume legitimate file transfer / video streaming",
                    ),
                    is_available=True,
                )
            )
            
        if forecast_deltas is not None and feature_names is not None:
            f_list = list(feature_names)
            if "byte_rate" in f_list:
                byte_idx = f_list.index("byte_rate")
                for h in range(forecast_deltas.shape[0]):
                    d_byte = float(forecast_deltas[h, byte_idx])
                    if d_byte >= 30000.0:
                        signatures.append(
                            BehaviouralSignature(
                                signature_id=new_id(f"sig-exfil-fc-h{h+1}"),
                                signature_type=SignatureType.EXFILTRATION_OUTBOUND_SURGE,
                                scope=EvidenceScope.FORECAST,
                                horizon_step=h + 1,
                                timestamp=cur_time,
                                current_values={"byte_rate": byte_rate},
                                predicted_deltas={"byte_rate_delta": d_byte},
                                direction=EvidenceDirection.UP,
                                supporting_features=("byte_rate",),
                                evidence_strength=EvidenceStrength.HIGH if d_byte >= 80000.0 else EvidenceStrength.MEDIUM,
                                uncertainty=uncertainty * (h + 1),
                                trust_level=trust_level,
                                explanation=f"Forecast h={h+1} predicts accelerating outbound volumetric surge (Δ +{d_byte:,.0f} B/s).",
                                alternative_explanations=("Scheduled backup job commencing",),
                                is_available=True,
                            )
                        )

        # 4. Timing / Periodic Anomaly Signature
        iat_mean = c_vals.get("iat_mean", 0.0)
        iat_std = c_vals.get("iat_std", 0.0)
        
        if flows >= 40.0 and iat_std <= 0.10 and iat_mean <= 1.0:
            signatures.append(
                BehaviouralSignature(
                    signature_id=new_id("sig-timing-cur"),
                    signature_type=SignatureType.TIMING_BEHAVIOURAL_ANOMALY,
                    scope=EvidenceScope.CURRENT,
                    horizon_step=0,
                    timestamp=cur_time,
                    current_values={"iat_mean": iat_mean, "iat_std": iat_std, "flow_count": flows},
                    predicted_deltas={},
                    direction=EvidenceDirection.DOWN,
                    supporting_features=("iat_mean", "iat_std", "flow_count"),
                    evidence_strength=EvidenceStrength.MEDIUM,
                    uncertainty=0.12,
                    trust_level=trust_level,
                    explanation=f"Unusually rigid, low-jitter flow inter-arrival times (mean {iat_mean:.3f}s, std {iat_std:.3f}s) indicating automated periodic transmission.",
                    alternative_explanations=(
                        "Automated telemetry heartbeat / NTP time sync poll",
                        "Scheduled cron-job monitoring probe",
                        "Regular application health-check ping",
                    ),
                    is_available=True,
                )
            )

        # 5. Lateral Fan-Out (Always checked for availability)
        if current_state.feature_availability.get("fan_out", FeatureAvailability.AVAILABLE) == FeatureAvailability.UNAVAILABLE:
            signatures.append(
                BehaviouralSignature(
                    signature_id=new_id("sig-lateral-unavail"),
                    signature_type=SignatureType.LATERAL_FAN_OUT,
                    scope=EvidenceScope.CURRENT,
                    horizon_step=0,
                    timestamp=cur_time,
                    current_values={},
                    predicted_deltas={},
                    direction=EvidenceDirection.STABLE,
                    supporting_features=("fan_out", "src_ip_diversity", "dst_ip_diversity"),
                    evidence_strength=EvidenceStrength.UNKNOWN,
                    uncertainty=1.0,
                    trust_level=TrustLevel.INSUFFICIENT,
                    explanation="Topology telemetry UNAVAILABLE in current CSV flow source; Lateral fan-out cannot be evaluated.",
                    alternative_explanations=(),
                    is_available=False,
                )
            )

        return signatures

    def infer_stage_hypotheses(
        self,
        signatures: Sequence[BehaviouralSignature],
        trust_level: TrustLevel = TrustLevel.MEDIUM,
    ) -> list[StageHypothesis]:
        """
        Infer ranked candidate stage hypotheses from active signatures.
        Unknown is always represented as a valid hypothesis.
        """
        active_sigs = [s for s in signatures if s.is_available and s.evidence_strength in (EvidenceStrength.HIGH, EvidenceStrength.MEDIUM, EvidenceStrength.LOW)]
        hypotheses: list[StageHypothesis] = []
        
        # 1. Reconnaissance Hypothesis
        recon_sigs = [s for s in active_sigs if s.signature_type == SignatureType.RECONNAISSANCE_PORT_EXPLORATION]
        if recon_sigs:
            has_cur = any(s.scope == EvidenceScope.CURRENT for s in recon_sigs)
            has_fc_up = any(s.scope == EvidenceScope.FORECAST and s.direction == EvidenceDirection.UP for s in recon_sigs)
            has_fc_down = any(s.scope == EvidenceScope.FORECAST and s.direction == EvidenceDirection.DOWN for s in recon_sigs)
            
            counter_ev = ["Target endpoints responding normally", "No lateral fan-out telemetry available"]
            if has_cur and has_fc_up:
                conf = 0.85  # Current elevated AND forecast expanding
            elif has_cur and has_fc_down:
                conf = 0.40  # Contradictory forecast predicts rapid decay
                counter_ev.append("Forecast predicts immediate deceleration / mean-reversion to baseline")
            elif any(s.evidence_strength == EvidenceStrength.HIGH for s in recon_sigs):
                conf = 0.75
            else:
                conf = 0.55
                
            hypotheses.append(
                StageHypothesis(
                    hypothesis_id=new_id("hyp-recon"),
                    candidate_stage="Reconnaissance",
                    supporting_signatures=tuple(recon_sigs),
                    counter_evidence=tuple(counter_ev),
                    confidence=conf,
                    trust_level=trust_level,
                    alternative_explanations=(
                        "Service discovery / network inventory scanning",
                        "Administrative vulnerability assessment",
                    ),
                    is_primary=False,
                )
            )

        # 2. Denial of Service / Resource Pressure Hypothesis
        flood_sigs = [s for s in active_sigs if s.signature_type == SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE]
        if flood_sigs:
            has_cur = any(s.scope == EvidenceScope.CURRENT for s in flood_sigs)
            has_fc_up = any(s.scope == EvidenceScope.FORECAST and s.direction == EvidenceDirection.UP for s in flood_sigs)
            has_fc_down = any(s.scope == EvidenceScope.FORECAST and s.direction == EvidenceDirection.DOWN for s in flood_sigs)
            
            counter_ev = ["No complete service outage confirmed", "Packet rate within transport headroom"]
            if has_cur and has_fc_up:
                conf = 0.85
            elif has_cur and has_fc_down:
                conf = 0.40
                counter_ev.append("Forecast predicts burst completion and return to baseline")
            elif any(s.evidence_strength == EvidenceStrength.HIGH for s in flood_sigs):
                conf = 0.70
            else:
                conf = 0.50
                
            hypotheses.append(
                StageHypothesis(
                    hypothesis_id=new_id("hyp-dos"),
                    candidate_stage="Impact / Denial of Service",
                    supporting_signatures=tuple(flood_sigs),
                    counter_evidence=tuple(counter_ev),
                    confidence=conf,
                    trust_level=trust_level,
                    alternative_explanations=(
                        "Legitimate high-volume user traffic surge",
                        "Misconfigured service retry storm",
                    ),
                    is_primary=False,
                )
            )

        # 3. Collection / Exfiltration Hypothesis
        exfil_sigs = [s for s in active_sigs if s.signature_type == SignatureType.EXFILTRATION_OUTBOUND_SURGE]
        if exfil_sigs:
            has_cur = any(s.scope == EvidenceScope.CURRENT for s in exfil_sigs)
            has_fc_up = any(s.scope == EvidenceScope.FORECAST and s.direction == EvidenceDirection.UP for s in exfil_sigs)
            
            counter_ev = ["Transfer volume consistent with routine backup schedule"]
            if has_cur and has_fc_up:
                conf = 0.80
            elif any(s.evidence_strength == EvidenceStrength.HIGH for s in exfil_sigs):
                conf = 0.65
            else:
                conf = 0.45
                
            hypotheses.append(
                StageHypothesis(
                    hypothesis_id=new_id("hyp-exfil"),
                    candidate_stage="Collection / Exfiltration",
                    supporting_signatures=tuple(exfil_sigs),
                    counter_evidence=tuple(counter_ev),
                    confidence=conf,
                    trust_level=trust_level,
                    alternative_explanations=(
                        "Scheduled database archive replication",
                        "Software distribution repository synchronization",
                    ),
                    is_primary=False,
                )
            )

        # 4. Command and Control / Periodic Beaconing
        timing_sigs = [s for s in active_sigs if s.signature_type == SignatureType.TIMING_BEHAVIOURAL_ANOMALY]
        if timing_sigs:
            hypotheses.append(
                StageHypothesis(
                    hypothesis_id=new_id("hyp-c2"),
                    candidate_stage="Initial Access / Delivery",
                    supporting_signatures=tuple(timing_sigs),
                    counter_evidence=("Payload contents uninspected in NetFlow aggregation",),
                    confidence=0.40,
                    trust_level=trust_level,
                    alternative_explanations=(
                        "Automated telemetry heartbeat polling",
                        "NTP synchronization client",
                    ),
                    is_primary=False,
                )
            )

        # 5. Default Unknown Hypothesis (Always included)
        unknown_conf = 0.85 if len(hypotheses) == 0 else 0.15
        unknown_hyp = StageHypothesis(
            hypothesis_id=new_id("hyp-unknown"),
            candidate_stage="Unknown",
            supporting_signatures=(),
            counter_evidence=(),
            confidence=unknown_conf,
            trust_level=trust_level,
            alternative_explanations=("Benign baseline operational traffic", "Insufficient behavioural deviation"),
            is_primary=len(hypotheses) == 0,
        )
        
        if not hypotheses:
            return [unknown_hyp]
            
        # Sort hypotheses by confidence descending
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        # Mark top hypothesis as primary
        primary_hyp = StageHypothesis(
            hypothesis_id=hypotheses[0].hypothesis_id,
            candidate_stage=hypotheses[0].candidate_stage,
            supporting_signatures=hypotheses[0].supporting_signatures,
            counter_evidence=hypotheses[0].counter_evidence,
            confidence=hypotheses[0].confidence,
            trust_level=hypotheses[0].trust_level,
            alternative_explanations=hypotheses[0].alternative_explanations,
            is_primary=True,
        )
        result = [primary_hyp] + list(hypotheses[1:]) + [unknown_hyp]
        return result

    def map_to_attack_techniques(
        self,
        signatures: Sequence[BehaviouralSignature],
    ) -> list[AttackTechniqueHypothesis]:
        """
        Map behavioural signatures to candidate MITRE ATT&CK techniques.
        Maintained as a separate explanatory mapping layer.
        """
        techniques: list[AttackTechniqueHypothesis] = []
        active_types = {s.signature_type for s in signatures if s.is_available and s.evidence_strength in (EvidenceStrength.HIGH, EvidenceStrength.MEDIUM, EvidenceStrength.LOW)}
        
        # T1046: Network Service Discovery
        if SignatureType.RECONNAISSANCE_PORT_EXPLORATION in active_types:
            techniques.append(
                AttackTechniqueHypothesis(
                    technique_id="T1046",
                    technique_name="Network Service Discovery",
                    tactic_name="Discovery",
                    supporting_signatures=("RECONNAISSANCE_PORT_EXPLORATION",),
                    confidence=0.70,
                    rationale="Elevated destination port diversity across flows indicates systematic probing of host services.",
                    limitations="Source IP identity and scan tooling headers are unavailable in current flow telemetry.",
                    is_available=True,
                )
            )

        # T1498: Network Denial of Service
        if SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE in active_types:
            techniques.append(
                AttackTechniqueHypothesis(
                    technique_id="T1498",
                    technique_name="Network Denial of Service",
                    tactic_name="Impact",
                    supporting_signatures=("CONNECTION_FLOODING_RESOURCE_PRESSURE",),
                    confidence=0.65,
                    rationale="High connection flow rate with elevated TCP reset/rejection ratio indicates service flooding.",
                    limitations="Cannot distinguish intentional DDoS attack from legitimate high-load flash event without application error logs.",
                    is_available=True,
                )
            )

        # T1048: Exfiltration Over Alternative Protocol
        if SignatureType.EXFILTRATION_OUTBOUND_SURGE in active_types:
            techniques.append(
                AttackTechniqueHypothesis(
                    technique_id="T1048",
                    technique_name="Exfiltration Over Alternative Protocol",
                    tactic_name="Exfiltration",
                    supporting_signatures=("EXFILTRATION_OUTBOUND_SURGE",),
                    confidence=0.60,
                    rationale="High sustained byte transfer rate with large mean packet payload size indicates substantial outbound data staging.",
                    limitations="L7 payload inspection and destination external IP geolocation are unavailable in CSV flow data.",
                    is_available=True,
                )
            )

        # T1071: Application Layer Protocol (C2 Beaconing)
        if SignatureType.TIMING_BEHAVIOURAL_ANOMALY in active_types:
            techniques.append(
                AttackTechniqueHypothesis(
                    technique_id="T1071",
                    technique_name="Application Layer Protocol",
                    tactic_name="Command and Control",
                    supporting_signatures=("TIMING_BEHAVIOURAL_ANOMALY",),
                    confidence=0.45,
                    rationale="Rigid flow inter-arrival timing suggests periodic machine-generated communication.",
                    limitations="Interval regularity alone cannot prove malicious C2 protocol without payload analysis.",
                    is_available=True,
                )
            )

        # T1021: Remote Services / Lateral Movement (Unavailable)
        techniques.append(
            AttackTechniqueHypothesis(
                technique_id="T1021",
                technique_name="Remote Services",
                tactic_name="Lateral Movement",
                supporting_signatures=("LATERAL_FAN_OUT",),
                confidence=0.0,
                rationale="Lateral movement evaluation requires internal IP tracking and endpoint fan-out.",
                limitations="UNAVAILABLE: Endpoint IP addresses and internal routing topology are absent in current dataset.",
                is_available=False,
            )
        )

        return techniques

    def build_security_assessment(
        self,
        trajectory: Trajectory,
        trust_assessment: TrustAssessment,
        signatures: Sequence[BehaviouralSignature],
        stage_hypotheses: Sequence[StageHypothesis],
    ) -> SecurityAssessment:
        """
        Construct a valid SecurityAssessment satisfying all core/contracts.py invariants.
        """
        # Build candidate stages list ensuring Unknown is present and primary is first
        cand_stages = []
        for h in stage_hypotheses:
            cand_stages.append(
                StageCandidate(
                    stage_name=h.candidate_stage,
                    attack_technique_id=None,
                    evidence_score=float(h.confidence),
                    is_primary=h.is_primary,
                )
            )
            
        if not any(c.stage_name == "Unknown" for c in cand_stages):
            cand_stages.append(StageCandidate(stage_name="Unknown", attack_technique_id=None, evidence_score=0.10, is_primary=False))
            
        # Ensure primary stage is at index 0
        cand_stages.sort(key=lambda c: (not c.is_primary, -c.evidence_score))
        primary_stage = cand_stages[0]
        
        # Build evidence items
        evidence_items = []
        for s in signatures:
            if s.is_available and s.evidence_strength in (EvidenceStrength.HIGH, EvidenceStrength.MEDIUM):
                for f_name in s.supporting_features:
                    val = float(s.current_values.get(f_name, 0.0))
                    evidence_items.append(
                        EvidenceItem(
                            feature_name=f_name,
                            feature_value=val,
                            direction=s.direction,
                            contribution=float(0.80 if s.evidence_strength == EvidenceStrength.HIGH else 0.50),
                        )
                    )
                    
        # Summary dict of behavioural signatures
        sig_summary = {
            s.signature_type.value: float(1.0 if s.evidence_strength == EvidenceStrength.HIGH else (0.5 if s.evidence_strength == EvidenceStrength.MEDIUM else 0.2))
            for s in signatures if s.is_available
        }
        
        return SecurityAssessment(
            assessment_id=new_id("sec-eval"),
            trajectory_id=trajectory.trajectory_id,
            trust_assessment_id=trust_assessment.assessment_id,
            behavioural_signature=sig_summary,
            candidate_stages=cand_stages,
            primary_stage=primary_stage,
            evidence_summary=evidence_items,
            is_novel=False,
        )

    def compute_security_risk_trajectory(
        self,
        current_state: NetworkState,
        stage_hypotheses: Sequence[StageHypothesis],
        trust_assessment: TrustAssessment,
        signatures: Sequence[BehaviouralSignature] | None = None,
        max_horizon: int = 3,
    ) -> SecurityRiskTrajectory:
        """
        Compute bounded, explainable future security-risk scores R(t+h) for h in {0, 1, 2, 3}.
        """
        risk_engine = SecurityRiskEngine()
        return risk_engine.compute_risk_trajectory(
            current_state=current_state,
            stage_hypotheses=stage_hypotheses,
            trust_assessment=trust_assessment,
            signatures=signatures,
            max_horizon=max_horizon,
        )

