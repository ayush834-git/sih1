"""Bi-directional flow accumulation with exact CICFlowMeter semantics (SIH 26153)."""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from statistics import fmean, pstdev
from typing import Dict, List, Sequence, Tuple

from runtime.live.packet_parser import ParsedPacket


# Canonical bi-directional flow key: ((endpoint1), (endpoint2), protocol)
FlowKey = Tuple[Tuple[str, int], Tuple[str, int], int]


def make_canonical_flow_key(packet: ParsedPacket) -> FlowKey:
    """Create order-independent bi-directional flow key."""
    ep1 = (packet.src_ip, packet.src_port)
    ep2 = (packet.dst_ip, packet.dst_port)
    if ep1 <= ep2:
        return (ep1, ep2, packet.protocol)
    return (ep2, ep1, packet.protocol)


@dataclass
class FlowRecord:
    """Represents a bi-directional TCP/IP flow matching CICFlowMeter fields."""
    flow_key: FlowKey
    initiator_src_ip: str
    initiator_src_port: int
    initiator_dst_ip: str
    initiator_dst_port: int
    protocol: int
    start_time: float
    last_time: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    retransmit_count: int = 0
    packet_timestamps: List[float] = field(default_factory=list)
    packet_lengths: List[int] = field(default_factory=list)
    packet_hashes: List[str] = field(default_factory=list)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def duration_s(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    @property
    def dst_port(self) -> int:
        return self.initiator_dst_port

    @property
    def fwd_bwd_packet_ratio(self) -> float:
        """Ratio of forward to backward packets."""
        return float(self.fwd_packets) / max(1, self.bwd_packets)

    @property
    def fwd_bwd_byte_ratio(self) -> float:
        """Ratio of forward to backward bytes."""
        return float(self.fwd_bytes) / max(1, self.bwd_bytes)

    @property
    def fwd_packet_ratio(self) -> float:
        """Ratio of forward packets to total packets."""
        return float(self.fwd_packets) / max(1, self.total_packets)

    @property
    def bwd_packet_ratio(self) -> float:
        """Ratio of backward packets to total packets."""
        return float(self.bwd_packets) / max(1, self.total_packets)

    @property
    def fwd_byte_ratio(self) -> float:
        """Ratio of forward bytes to total bytes."""
        return float(self.fwd_bytes) / max(1, self.total_bytes)

    @property
    def bwd_byte_ratio(self) -> float:
        """Ratio of backward bytes to total bytes."""
        return float(self.bwd_bytes) / max(1, self.total_bytes)

    def compute_iat_stats(self) -> Tuple[float, float]:
        """Compute Flow IAT Mean and Flow IAT Std in seconds."""
        if len(self.packet_timestamps) < 2:
            return 0.0, 0.0
        iats = [
            self.packet_timestamps[i] - self.packet_timestamps[i - 1]
            for i in range(1, len(self.packet_timestamps))
        ]
        mean_val = fmean(iats)
        std_val = pstdev(iats) if len(iats) > 1 else 0.0
        return mean_val, std_val

    def compute_extended_iat_stats(self) -> Tuple[float, float, float, float]:
        """Compute Flow IAT (Mean, Std, Max, Variance) in seconds."""
        if len(self.packet_timestamps) < 2:
            return 0.0, 0.0, 0.0, 0.0
        iats = [
            self.packet_timestamps[i] - self.packet_timestamps[i - 1]
            for i in range(1, len(self.packet_timestamps))
        ]
        mean_val = fmean(iats)
        std_val = pstdev(iats) if len(iats) > 1 else 0.0
        max_val = max(iats)
        var_val = std_val ** 2
        return mean_val, std_val, max_val, var_val

    def compute_pkt_len_stats(self) -> Tuple[float, float]:
        """Compute Pkt Len Mean and Pkt Len Std in bytes."""
        if not self.packet_lengths:
            return 0.0, 0.0
        mean_val = fmean(self.packet_lengths)
        std_val = pstdev(self.packet_lengths) if len(self.packet_lengths) > 1 else 0.0
        return mean_val, std_val

    def compute_extended_pkt_len_stats(self) -> Tuple[float, float, float, float]:
        """Compute Pkt Len (Mean, Std, Max, Min) in bytes."""
        if not self.packet_lengths:
            return 0.0, 0.0, 0.0, 0.0
        mean_val = fmean(self.packet_lengths)
        std_val = pstdev(self.packet_lengths) if len(self.packet_lengths) > 1 else 0.0
        return mean_val, std_val, float(max(self.packet_lengths)), float(min(self.packet_lengths))

    def get_flow_features(self) -> Dict[str, float]:
        """Export comprehensive flow-level feature map adhering to PS 26153 specifications."""
        iat_mean, iat_std, iat_max, iat_var = self.compute_extended_iat_stats()
        pkt_mean, pkt_std, pkt_max, pkt_min = self.compute_extended_pkt_len_stats()
        return {
            "duration_s": self.duration_s,
            "total_fwd_packets": float(self.fwd_packets),
            "total_bwd_packets": float(self.bwd_packets),
            "total_fwd_bytes": float(self.fwd_bytes),
            "total_bwd_bytes": float(self.bwd_bytes),
            "fwd_bwd_packet_ratio": self.fwd_bwd_packet_ratio,
            "fwd_bwd_byte_ratio": self.fwd_bwd_byte_ratio,
            "fwd_packet_ratio": self.fwd_packet_ratio,
            "bwd_packet_ratio": self.bwd_packet_ratio,
            "fwd_byte_ratio": self.fwd_byte_ratio,
            "bwd_byte_ratio": self.bwd_byte_ratio,
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "iat_max": iat_max,
            "iat_variance": iat_var,
            "pkt_len_mean": pkt_mean,
            "pkt_len_std": pkt_std,
            "pkt_len_max": pkt_max,
            "pkt_len_min": pkt_min,
            "syn_count": float(self.syn_count),
            "ack_count": float(self.ack_count),
            "rst_count": float(self.rst_count),
            "fin_count": float(self.fin_count),
            "psh_count": float(self.psh_count),
            "urg_count": float(self.urg_count),
            "retransmit_count": float(self.retransmit_count),
        }


class FlowAccumulator:
    """Accumulates parsed packets into bi-directional flows."""

    def __init__(self) -> None:
        self.flows: Dict[FlowKey, FlowRecord] = {}

    def add_packet(self, packet: ParsedPacket) -> None:
        """Ingest a parsed packet into its corresponding bi-directional flow."""
        key = make_canonical_flow_key(packet)

        if key not in self.flows:
            # First packet seen for this flow defines the forward direction and initiator
            self.flows[key] = FlowRecord(
                flow_key=key,
                initiator_src_ip=packet.src_ip,
                initiator_src_port=packet.src_port,
                initiator_dst_ip=packet.dst_ip,
                initiator_dst_port=packet.dst_port,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                last_time=packet.timestamp,
            )

        flow = self.flows[key]
        flow.last_time = max(flow.last_time, packet.timestamp)
        flow.packet_timestamps.append(packet.timestamp)
        flow.packet_lengths.append(packet.frame_len)
        flow.packet_hashes.append(packet.packet_hash)

        # Check direction relative to flow initiator
        if packet.src_ip == flow.initiator_src_ip and packet.src_port == flow.initiator_src_port:
            flow.fwd_packets += 1
            flow.fwd_bytes += packet.frame_len
        else:
            flow.bwd_packets += 1
            flow.bwd_bytes += packet.frame_len

        # Accumulate TCP flags
        if packet.syn:
            flow.syn_count += 1
        if packet.ack:
            flow.ack_count += 1
        if packet.rst:
            flow.rst_count += 1
        if packet.fin:
            flow.fin_count += 1
        if packet.psh:
            flow.psh_count += 1
        if packet.urg:
            flow.urg_count += 1
        if packet.is_retransmission:
            flow.retransmit_count += 1

    def get_flows(self) -> Sequence[FlowRecord]:
        """Return all tracked flows."""
        return list(self.flows.values())

    def reset(self) -> None:
        """Clear all flows."""
        self.flows.clear()


def partition_packets_into_windows(
    packets: Sequence[ParsedPacket],
    window_duration_s: float = 10.0,
    start_time: float | None = None,
) -> Dict[int, List[ParsedPacket]]:
    """Strictly partition packets into causal, non-overlapping window bins.
    
    Bin index k covers [start_time + k * window_duration_s, start_time + (k + 1) * window_duration_s).
    """
    if not packets:
        return {}

    t0 = start_time if start_time is not None else packets[0].timestamp
    windows: Dict[int, List[ParsedPacket]] = {}

    for pkt in sorted(packets, key=lambda p: p.timestamp):
        offset = pkt.timestamp - t0
        idx = int(math.floor(offset / window_duration_s))
        if idx not in windows:
            windows[idx] = []
        windows[idx].append(pkt)

    return windows
