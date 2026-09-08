"""
Multi-Signal Causal Behavioral Normalization Bridge (SIH PS 26153).

A/B Research Experiment Candidate:
Evaluates whether causal, distribution-aware normalization across multiple
network-behaviour dimensions (destination port diversity, connection flow rate,
byte transfer rate, inter-arrival timing) can distinguish attack-related
behavioural change from normal temporal variation more effectively than a
port-diversity-only bridge, particularly for stealthy infiltration that does
not scan destination ports.

Strict Scope:
- Zero future leakage: Trailing historical window W only.
- Strict causality: State at window t is normalized against baseline computed
  strictly from observations prior to window t.
- Parameter selection provenance: W=30, k=3.0, and scale floors tuned strictly
  on pre-test split data (Thursday 04:00:00 to 08:00:00 UTC, N=625 windows).
- Transparent aggregation exposing per-feature contributions.
"""
from __future__ import annotations

import collections
from typing import Mapping, Sequence

import numpy as np

from core.contracts import (
    EvidenceDirection,
    NetworkState,
    TrustLevel,
    new_id,
)
from eval.metrics_v2 import RobustScaleStatistics
from security.bridge import BehavioralSecurityBridge
from security.contracts import (
    BehaviouralSignature,
    EvidenceScope,
    EvidenceStrength,
    SignatureType,
)


DEFAULT_SCALE_FLOORS: dict[str, float] = {
    "port": 2.0,    # dst_port_diversity floor
    "flow": 0.30,   # log1p(flow_count) floor
    "byte": 0.80,   # log1p(byte_rate) floor
    "timing": 0.50, # iat_mean floor in seconds
}


class MultiSignalRollingBaselineSecurityBridge(BehavioralSecurityBridge):
    """
    Candidate BehavioralSecurityBridge variant with multi-signal causal normalization.

    Maintains trailing causal baselines (median and MAD) across 4 orthogonal dimensions:
    1. 'port': dst_port_diversity (destination service exploration)
    2. 'flow': log1p(flow_count) (connection / resource demand)
    3. 'byte': log1p(byte_rate) (data transfer volume)
    4. 'timing': iat_mean (arrival timing compression: median - current)

    Exposes explicit named parameters and transparent per-feature attribution.
    """

    def __init__(
        self,
        scales: RobustScaleStatistics | None = None,
        rolling_window_length: int = 30,
        k_mad: float = 3.0,
        scale_floors: Mapping[str, float] | None = None,
        min_history: int = 5,
        active_signals: Sequence[str] = ("port", "flow", "byte", "timing"),
    ) -> None:
        super().__init__(scales=scales)
        self.rolling_window_length = int(rolling_window_length)
        self.k_mad = float(k_mad)
        self.scale_floors = dict(scale_floors or DEFAULT_SCALE_FLOORS)
        self.min_history = int(min_history)
        self.active_signals = tuple(active_signals)

        # Causal trailing history buffers
        self._history: dict[str, collections.deque[float]] = {
            "port": collections.deque(maxlen=self.rolling_window_length),
            "flow": collections.deque(maxlen=self.rolling_window_length),
            "byte": collections.deque(maxlen=self.rolling_window_length),
            "timing": collections.deque(maxlen=self.rolling_window_length),
        }

    def reset(self) -> None:
        """Clear all trailing rolling baseline buffers."""
        for q in self._history.values():
            q.clear()

    def get_signal_stats(self) -> dict[str, dict[str, float | bool]]:
        """
        Computes (median, MAD, scale, is_active) for each tracked dimension
        strictly from trailing history prior to current window.
        """
        stats_dict = {}
        for sig_name in ("port", "flow", "byte", "timing"):
            q = self._history[sig_name]
            if len(q) >= self.min_history:
                arr = np.array(q, dtype=np.float64)
                med = float(np.median(arr))
                mad = float(np.median(np.abs(arr - med)))
                floor_val = self.scale_floors.get(sig_name, 1.0)
                scale = max(1.4826 * mad, floor_val)
                stats_dict[sig_name] = {
                    "median": med,
                    "mad": mad,
                    "scale": scale,
                    "is_active": True,
                }
            else:
                stats_dict[sig_name] = {
                    "median": 0.0,
                    "mad": 0.0,
                    "scale": self.scale_floors.get(sig_name, 1.0),
                    "is_active": False,
                }
        return stats_dict

    def compute_causal_z_scores(
        self,
        current_state: NetworkState,
    ) -> dict[str, float]:
        """
        Computes robust causal z-scores for all active signals against trailing history.
        Does NOT modify history buffer.
        """
        c_vals = current_state.feature_values()
        stats_dict = self.get_signal_stats()

        raw_vals = {
            "port": float(c_vals.get("dst_port_diversity", 0.0)),
            "flow": float(np.log1p(c_vals.get("flow_count", 0.0))),
            "byte": float(np.log1p(c_vals.get("byte_rate", 0.0))),
            "timing": float(c_vals.get("iat_mean", 0.0)),
        }

        z_scores = {}
        for sig_name in ("port", "flow", "byte", "timing"):
            if sig_name not in self.active_signals:
                z_scores[sig_name] = 0.0
                continue

            sig_st = stats_dict[sig_name]
            if sig_st["is_active"]:
                med = float(sig_st["median"])
                scale = float(sig_st["scale"])
                val = raw_vals[sig_name]
                # For timing: compression (lower IAT) indicates rapid bursts / automated flooding
                if sig_name == "timing":
                    z = (med - val) / scale
                else:
                    z = (val - med) / scale
                z_scores[sig_name] = max(0.0, float(z))
            else:
                z_scores[sig_name] = 0.0

        return z_scores

    def aggregate_multi_signal_evidence(
        self,
        z_scores: Mapping[str, float],
    ) -> tuple[float, str, dict[str, float]]:
        """
        Transparent aggregation exposing per-feature contributions.
        composite_z = max_z + 0.35 * sum_{other}(max(0, z - 1.5))

        Returns (composite_z, primary_contributor, contribution_dict).
        """
        active_z = {k: float(v) for k, v in z_scores.items() if k in self.active_signals}
        if not active_z or all(v <= 0.0 for v in active_z.values()):
            return 0.0, "none", {k: 0.0 for k in self.active_signals}

        primary_sig = max(active_z, key=active_z.get)
        max_z = active_z[primary_sig]

        # Multi-signal synergy bonus for correlated deviations on secondary dimensions
        synergy_bonus = 0.0
        contributions = {}
        for k, z in active_z.items():
            if k == primary_sig:
                contributions[k] = round(max_z, 4)
            else:
                bonus = 0.35 * max(0.0, z - 1.5)
                synergy_bonus += bonus
                contributions[k] = round(bonus, 4)

        composite_z = max_z + synergy_bonus
        return float(composite_z), primary_sig, contributions

    def extract_signatures(
        self,
        current_state: NetworkState,
        forecast_deltas: np.ndarray | None = None,  # Shape: (H, n_features)
        feature_names: Sequence[str] | None = None,
        trust_level: TrustLevel = TrustLevel.MEDIUM,
        uncertainty: float = 0.20,
        update_baseline: bool = True,
    ) -> list[BehaviouralSignature]:
        """
        Extract deterministic behavioural signatures using multi-signal causal normalization.
        """
        c_vals = current_state.feature_values()
        cur_time = current_state.timestamp_end

        dst_ports = float(c_vals.get("dst_port_diversity", 0.0))
        flows = float(c_vals.get("flow_count", 0.0))
        bytes_sec = float(c_vals.get("byte_rate", 0.0))
        syn_ratio = float(c_vals.get("syn_ratio", 0.0))
        rst_ratio = float(c_vals.get("rst_ratio", 0.0))
        iat_mean = float(c_vals.get("iat_mean", 0.0))
        pkt_rate = float(c_vals.get("packet_rate", 0.0))
        pkt_size_mean = float(c_vals.get("pkt_size_mean", 0.0))

        # 1. Compute causal robust z-scores strictly from trailing history
        z_scores = self.compute_causal_z_scores(current_state)
        composite_z, primary_contributor, contributions = self.aggregate_multi_signal_evidence(z_scores)
        stats_dict = self.get_signal_stats()

        # 2. Update trailing history causally if requested (includes current window for future steps)
        if update_baseline:
            self._history["port"].append(dst_ports)
            self._history["flow"].append(float(np.log1p(flows)))
            self._history["byte"].append(float(np.log1p(bytes_sec)))
            self._history["timing"].append(iat_mean)

        signatures: list[BehaviouralSignature] = []
        is_warm = stats_dict["port"]["is_active"]

        # ── 1. Reconnaissance / Port Exploration Signature ──
        if "port" in self.active_signals and is_warm:
            port_elevated = z_scores["port"] >= self.k_mad
            port_high = z_scores["port"] >= (self.k_mad + 2.0) or syn_ratio >= 0.30
        else:
            # Warmup fallback
            port_elevated = dst_ports >= 15.0 or (dst_ports >= 8.0 and flows >= 30.0)
            port_high = dst_ports >= 25.0 or syn_ratio >= 0.30

        if port_elevated:
            strength = EvidenceStrength.HIGH if port_high else EvidenceStrength.MEDIUM
            med_p = stats_dict["port"]["median"]
            scale_p = stats_dict["port"]["scale"]
            signatures.append(
                BehaviouralSignature(
                    signature_id=new_id("sig-recon-cur"),
                    signature_type=SignatureType.RECONNAISSANCE_PORT_EXPLORATION,
                    scope=EvidenceScope.CURRENT,
                    horizon_step=0,
                    timestamp=cur_time,
                    current_values={
                        "dst_port_diversity": dst_ports,
                        "flow_count": flows,
                        "syn_ratio": syn_ratio,
                        "robust_z_port": round(z_scores.get("port", 0.0), 3),
                        "composite_z": round(composite_z, 3),
                    },
                    predicted_deltas={},
                    direction=EvidenceDirection.UP,
                    supporting_features=("dst_port_diversity", "flow_count", "syn_ratio"),
                    evidence_strength=strength,
                    uncertainty=0.10,
                    trust_level=trust_level,
                    explanation=(
                        f"Port diversity elevated ({dst_ports:.0f} ports, z_port={z_scores.get('port', 0.0):.2f} "
                        f"vs baseline median={med_p:.1f}, scale={scale_p:.1f}) with SYN ratio {syn_ratio:.2f}."
                    ),
                    alternative_explanations=(
                        "Legitimate microservice discovery / API probing",
                        "Administrative vulnerability scanning / asset inventory",
                        "Multi-tenant load balancer health monitoring",
                    ),
                    is_available=True,
                )
            )

        # ── 2. Connection Flooding / Resource Pressure Signature ──
        if "flow" in self.active_signals and is_warm:
            flow_elevated = z_scores["flow"] >= self.k_mad or (flows >= 80.0 and rst_ratio >= 0.15) or (flows >= 200.0)
            flow_high = z_scores["flow"] >= (self.k_mad + 2.0) or flows >= 200.0 or rst_ratio >= 0.30
        else:
            flow_elevated = (flows >= 80.0 and rst_ratio >= 0.15) or (flows >= 120.0 and syn_ratio >= 0.40) or (flows >= 200.0)
            flow_high = rst_ratio >= 0.30 or flows >= 200.0

        if flow_elevated:
            strength = EvidenceStrength.HIGH if flow_high else EvidenceStrength.MEDIUM
            signatures.append(
                BehaviouralSignature(
                    signature_id=new_id("sig-flood-cur"),
                    signature_type=SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE,
                    scope=EvidenceScope.CURRENT,
                    horizon_step=0,
                    timestamp=cur_time,
                    current_values={
                        "flow_count": flows,
                        "rst_ratio": rst_ratio,
                        "packet_rate": pkt_rate,
                        "robust_z_flow": round(z_scores.get("flow", 0.0), 3),
                        "composite_z": round(composite_z, 3),
                    },
                    predicted_deltas={},
                    direction=EvidenceDirection.UP,
                    supporting_features=("flow_count", "rst_ratio", "packet_rate"),
                    evidence_strength=strength,
                    uncertainty=0.10,
                    trust_level=trust_level,
                    explanation=(
                        f"Connection volume elevated ({flows:.0f} flows, z_flow={z_scores.get('flow', 0.0):.2f}, "
                        f"{pkt_rate:.1f} pkts/s) with RST ratio {rst_ratio:.2f}."
                    ),
                    alternative_explanations=(
                        "Legitimate flash crowd / surge in client traffic",
                        "Misconfigured client retry loop against failing service",
                        "Upstream firewall / gateway TCP session table exhaustion",
                    ),
                    is_available=True,
                )
            )

        # ── 3. Exfiltration-like Outbound Surge Signature ──
        if "byte" in self.active_signals and is_warm:
            byte_elevated = z_scores["byte"] >= self.k_mad or (bytes_sec >= 50000.0 and pkt_size_mean >= 300.0)
            byte_high = z_scores["byte"] >= (self.k_mad + 2.0) or bytes_sec >= 150000.0
        else:
            byte_elevated = bytes_sec >= 50000.0 and pkt_size_mean >= 300.0
            byte_high = bytes_sec >= 150000.0

        if byte_elevated:
            strength = EvidenceStrength.HIGH if byte_high else EvidenceStrength.MEDIUM
            signatures.append(
                BehaviouralSignature(
                    signature_id=new_id("sig-exfil-cur"),
                    signature_type=SignatureType.EXFILTRATION_OUTBOUND_SURGE,
                    scope=EvidenceScope.CURRENT,
                    horizon_step=0,
                    timestamp=cur_time,
                    current_values={
                        "byte_rate": bytes_sec,
                        "pkt_size_mean": pkt_size_mean,
                        "robust_z_byte": round(z_scores.get("byte", 0.0), 3),
                        "composite_z": round(composite_z, 3),
                    },
                    predicted_deltas={},
                    direction=EvidenceDirection.UP,
                    supporting_features=("byte_rate", "pkt_size_mean"),
                    evidence_strength=strength,
                    uncertainty=0.15,
                    trust_level=trust_level,
                    explanation=(
                        f"Outbound transfer rate elevated ({bytes_sec:,.0f} B/s, z_byte={z_scores.get('byte', 0.0):.2f}, "
                        f"pkt_size_mean={pkt_size_mean:.1f}B)."
                    ),
                    alternative_explanations=(
                        "Scheduled database replication / cloud snapshot backup",
                        "Operating system / container image update synchronization",
                        "High-volume legitimate file transfer / video streaming",
                    ),
                    is_available=True,
                )
            )

        # ── 4. Timing / Periodic Anomaly Signature ──
        if "timing" in self.active_signals and is_warm:
            timing_elevated = z_scores["timing"] >= self.k_mad or (flows >= 40.0 and c_vals.get("iat_std", 1.0) <= 0.10 and iat_mean <= 1.0)
            timing_high = z_scores["timing"] >= (self.k_mad + 2.0)
        else:
            timing_elevated = flows >= 40.0 and c_vals.get("iat_std", 1.0) <= 0.10 and iat_mean <= 1.0
            timing_high = False

        if timing_elevated:
            strength = EvidenceStrength.HIGH if timing_high else EvidenceStrength.MEDIUM
            signatures.append(
                BehaviouralSignature(
                    signature_id=new_id("sig-timing-cur"),
                    signature_type=SignatureType.TIMING_BEHAVIOURAL_ANOMALY,
                    scope=EvidenceScope.CURRENT,
                    horizon_step=0,
                    timestamp=cur_time,
                    current_values={
                        "iat_mean": iat_mean,
                        "flow_count": flows,
                        "robust_z_timing": round(z_scores.get("timing", 0.0), 3),
                        "composite_z": round(composite_z, 3),
                    },
                    predicted_deltas={},
                    direction=EvidenceDirection.DOWN,
                    supporting_features=("iat_mean", "flow_count"),
                    evidence_strength=strength,
                    uncertainty=0.12,
                    trust_level=trust_level,
                    explanation=(
                        f"Flow inter-arrival time compressed ({iat_mean:.3f}s, z_timing={z_scores.get('timing', 0.0):.2f}) "
                        f"indicating rapid burst sequencing across {flows:.0f} flows."
                    ),
                    alternative_explanations=(
                        "Automated telemetry heartbeat / NTP time sync poll",
                        "Scheduled cron-job monitoring probe",
                        "Regular application health-check ping",
                    ),
                    is_available=True,
                )
            )

        # ── 5. Forecast Evidence & Contradiction Handling (Experiment D Safety) ──
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
                                alternative_explanations=("Expanding legitimate service discovery sweep",),
                                is_available=True,
                            )
                        )
                    elif d_port <= -5.0 and port_elevated:
                        # Contradictory forecast: current elevated above rolling baseline but forecast dropping sharply
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
                                explanation=f"Forecast h={h+1} predicts connection flooding surge (Δ +{d_flow:.0f} flows).",
                                alternative_explanations=("Anticipated surge in user traffic",),
                                is_available=True,
                            )
                        )

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
                                current_values={"byte_rate": bytes_sec},
                                predicted_deltas={"byte_rate_delta": d_byte},
                                direction=EvidenceDirection.UP,
                                supporting_features=("byte_rate",),
                                evidence_strength=EvidenceStrength.HIGH if d_byte >= 80000.0 else EvidenceStrength.MEDIUM,
                                uncertainty=uncertainty * (h + 1),
                                trust_level=trust_level,
                                explanation=f"Forecast h={h+1} predicts outbound volumetric surge (Δ +{d_byte:,.0f} B/s).",
                                alternative_explanations=("Scheduled backup job commencing",),
                                is_available=True,
                            )
                        )

        # ── 6. Lateral Fan-Out (Always UNAVAILABLE in NetFlow CSV source) ──
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
                explanation="Topology telemetry UNAVAILABLE in CSV source; Lateral fan-out cannot be evaluated.",
                alternative_explanations=(),
                is_available=False,
            )
        )

        return signatures
