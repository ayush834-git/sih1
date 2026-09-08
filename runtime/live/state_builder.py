"""Constructs schema-compliant NetworkState from live observed packets and flows (SIH 26153)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from statistics import fmean, pstdev
from typing import Mapping, Sequence

from core.contracts import (
    FeatureAvailability,
    NetworkState,
    Source,
    STATE_FEATURES,
)
from eval.dataset import CSV_AVAILABLE_FEATURES
from runtime.live.flow_accumulator import FlowAccumulator, FlowRecord
from runtime.live.packet_parser import ParsedPacket


TOPOLOGY_FEATURES = (
    "src_ip_diversity",
    "dst_ip_diversity",
    "src_port_diversity",
    "fan_out",
    "internal_ratio",
    "east_west_count",
)


def _compute_skew(values: Sequence[float]) -> float | None:
    if len(values) < 3:
        return None
    mean = fmean(values)
    std = pstdev(values)
    if std == 0.0:
        return 0.0
    return fmean([(x - mean) ** 3 for x in values]) / (std ** 3)


def build_network_state_from_packets(
    packets: Sequence[ParsedPacket],
    start_time: datetime,
    end_time: datetime,
    window_index: int = 0,
    session_id: str = "live-capture-session",
    window_duration_s: float = 10.0,
) -> NetworkState:
    """Construct a validated, schema-compliant NetworkState strictly from packets observed in [start_time, end_time).
    
    Adheres strictly to the training representation and contract:
    - 15 predictive features derived with exact mathematical equivalence to CICFlowMeter / ingest/cic_flow.py.
    - Unavailable topology features explicitly set to None and marked UNAVAILABLE (no fabrication).
    - Source marked as Source.PCAP.
    - Provenance hash computed deterministically from observed packet hashes.
    """
    window_id = f"live_w{window_index:04d}_{start_time.strftime('%Y%m%d_%H%M%S')}_{int(window_duration_s)}s"

    # Compute provenance hash over all packets in this window
    if packets:
        packet_hashes_concat = "|".join(p.packet_hash for p in packets)
        provenance_hash = hashlib.sha256(packet_hashes_concat.encode()).hexdigest()
    else:
        provenance_hash = hashlib.sha256(f"empty_window_{window_id}".encode()).hexdigest()

    # Initial feature availability mapping
    feature_avail: dict[str, FeatureAvailability] = {
        name: FeatureAvailability.UNAVAILABLE for name in TOPOLOGY_FEATURES
    }

    if not packets:
        # Empty/idle window representation
        for f in CSV_AVAILABLE_FEATURES:
            feature_avail[f] = FeatureAvailability.UNAVAILABLE

        return NetworkState(
            window_id=window_id,
            timestamp_start=start_time,
            timestamp_end=end_time,
            window_duration_s=window_duration_s,
            flow_count=0,
            byte_rate=0.0,
            packet_rate=0.0,
            mean_flow_duration=0.0,
            src_ip_diversity=None,
            dst_ip_diversity=None,
            src_port_diversity=None,
            dst_port_diversity=0,
            fan_out=None,
            internal_ratio=None,
            east_west_count=None,
            syn_count=0,
            ack_count=0,
            rst_count=0,
            syn_ratio=0.0,
            rst_ratio=0.0,
            iat_mean=0.0,
            iat_std=0.0,
            iat_skew=None,
            pkt_size_mean=0.0,
            pkt_size_std=0.0,
            byte_variance=0.0,
            ttl_mean=None,
            ttl_variance=None,
            tcp_window_mean=None,
            fragment_count=None,
            retransmit_count=None,
            payload_size_mean=None,
            source=Source.PCAP,
            data_quality=0.0,
            is_empty=True,
            gap_before=False,
            gap_after=False,
            session_id=session_id,
            provenance_hash=provenance_hash,
            feature_availability=feature_avail,
        )

    # Accumulate flows from packets
    accumulator = FlowAccumulator()
    for pkt in packets:
        accumulator.add_packet(pkt)
    flows = accumulator.get_flows()

    flow_count = len(flows)
    feature_avail["flow_count"] = FeatureAvailability.AVAILABLE

    total_bytes = sum(f.total_bytes for f in flows)
    byte_rate = total_bytes / window_duration_s
    feature_avail["byte_rate"] = FeatureAvailability.AVAILABLE

    total_packets = sum(f.total_packets for f in flows)
    packet_rate = total_packets / window_duration_s
    feature_avail["packet_rate"] = FeatureAvailability.AVAILABLE

    flow_durations = [f.duration_s for f in flows]
    mean_flow_duration = fmean(flow_durations) if flow_durations else 0.0
    feature_avail["mean_flow_duration"] = FeatureAvailability.AVAILABLE

    dst_ports = [f.dst_port for f in flows]
    dst_port_diversity = len(set(dst_ports)) if dst_ports else 0
    feature_avail["dst_port_diversity"] = FeatureAvailability.AVAILABLE

    syn_count = sum(f.syn_count for f in flows)
    ack_count = sum(f.ack_count for f in flows)
    rst_count = sum(f.rst_count for f in flows)
    feature_avail["syn_count"] = FeatureAvailability.AVAILABLE
    feature_avail["ack_count"] = FeatureAvailability.AVAILABLE
    feature_avail["rst_count"] = FeatureAvailability.AVAILABLE

    syn_ratio = min(1.0, max(0.0, syn_count / total_packets)) if total_packets > 0 else 0.0
    rst_ratio = min(1.0, max(0.0, rst_count / total_packets)) if total_packets > 0 else 0.0
    feature_avail["syn_ratio"] = FeatureAvailability.AVAILABLE
    feature_avail["rst_ratio"] = FeatureAvailability.AVAILABLE

    # Flow IAT statistics
    iat_stats = [f.compute_iat_stats() for f in flows]
    iat_means = [s[0] for s in iat_stats]
    iat_stds = [s[1] for s in iat_stats]
    iat_mean = fmean(iat_means) if iat_means else 0.0
    iat_std = fmean(iat_stds) if iat_stds else 0.0
    iat_skew = _compute_skew(iat_means) if len(iat_means) >= 3 else None
    feature_avail["iat_mean"] = FeatureAvailability.AVAILABLE
    feature_avail["iat_std"] = FeatureAvailability.AVAILABLE

    # Packet size statistics
    pkt_stats = [f.compute_pkt_len_stats() for f in flows]
    pkt_means = [s[0] for s in pkt_stats]
    pkt_stds = [s[1] for s in pkt_stats]
    pkt_size_mean = fmean(pkt_means) if pkt_means else 0.0
    pkt_size_std = fmean(pkt_stds) if pkt_stds else 0.0
    feature_avail["pkt_size_mean"] = FeatureAvailability.AVAILABLE
    feature_avail["pkt_size_std"] = FeatureAvailability.AVAILABLE

    # Flow byte variance
    flow_bytes = [f.total_bytes for f in flows]
    if len(flow_bytes) > 1:
        byte_variance = pstdev(flow_bytes) ** 2
    else:
        byte_variance = 0.0
    feature_avail["byte_variance"] = FeatureAvailability.AVAILABLE

    # Auxiliary observed wire attributes
    ttls = [p.ttl for p in packets if p.ttl is not None]
    ttl_mean = fmean(ttls) if ttls else None
    ttl_variance = (pstdev(ttls) ** 2) if len(ttls) > 1 else (0.0 if ttls else None)

    windows = [p.window_size for p in packets if p.window_size is not None]
    tcp_window_mean = fmean(windows) if windows else None

    payloads = [p.payload_len for p in packets]
    payload_size_mean = fmean(payloads) if payloads else None

    fragment_count = sum(1 for p in packets if getattr(p, "is_fragment", False) or getattr(p, "frag_offset", 0) > 0)
    retransmit_count = sum(1 for p in packets if getattr(p, "is_retransmission", False))

    # Calculate data quality
    avail_count = sum(1 for name in CSV_AVAILABLE_FEATURES if feature_avail.get(name) == FeatureAvailability.AVAILABLE)
    data_quality = avail_count / len(CSV_AVAILABLE_FEATURES)

    return NetworkState(
        window_id=window_id,
        timestamp_start=start_time,
        timestamp_end=end_time,
        window_duration_s=window_duration_s,
        flow_count=flow_count,
        byte_rate=byte_rate,
        packet_rate=packet_rate,
        mean_flow_duration=mean_flow_duration,
        src_ip_diversity=None,
        dst_ip_diversity=None,
        src_port_diversity=None,
        dst_port_diversity=dst_port_diversity,
        fan_out=None,
        internal_ratio=None,
        east_west_count=None,
        syn_count=syn_count,
        ack_count=ack_count,
        rst_count=rst_count,
        syn_ratio=syn_ratio,
        rst_ratio=rst_ratio,
        iat_mean=iat_mean,
        iat_std=iat_std,
        iat_skew=iat_skew,
        pkt_size_mean=pkt_size_mean,
        pkt_size_std=pkt_size_std,
        byte_variance=byte_variance,
        ttl_mean=ttl_mean,
        ttl_variance=ttl_variance,
        tcp_window_mean=tcp_window_mean,
        fragment_count=fragment_count,
        retransmit_count=retransmit_count,
        payload_size_mean=payload_size_mean,
        source=Source.PCAP,
        data_quality=data_quality,
        is_empty=False,
        gap_before=False,
        gap_after=False,
        session_id=session_id,
        provenance_hash=provenance_hash,
        feature_availability=feature_avail,
    )
