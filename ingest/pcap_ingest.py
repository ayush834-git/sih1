"""Offline PCAP ingestion pipeline producing schema-compliant NetworkState sequences (SIH 26153)."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Sequence

from core.contracts import NetworkState, Source
from runtime.live.backend import find_tshark_executable
from runtime.live.flow_accumulator import partition_packets_into_windows
from runtime.live.packet_parser import (
    ParsedPacket,
    TSHARK_FIELD_ARGS,
    parse_tshark_line,
)
from runtime.live.state_builder import build_network_state_from_packets


def read_packets_from_pcap(
    pcap_path: str | Path,
    tshark_path: str | None = None,
    bpf_filter: str | None = None,
) -> List[ParsedPacket]:
    """Read packets from an offline PCAP/PCAPNG file using TShark field parsing."""
    pcap_file = Path(pcap_path)
    if not pcap_file.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    bin_path = str(tshark_path or find_tshark_executable())
    if not bin_path or not Path(bin_path).exists():
        raise RuntimeError(f"TShark executable not available: {bin_path}")

    cmd = [bin_path, "-r", str(pcap_file)]
    if bpf_filter:
        cmd.extend(["-f", bpf_filter])
    cmd.extend(TSHARK_FIELD_ARGS)

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1024 * 1024,
    )

    packets: List[ParsedPacket] = []
    try:
        assert process.stdout is not None
        for line in process.stdout:
            pkt = parse_tshark_line(line)
            if pkt is not None:
                packets.append(pkt)
        process.wait(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()

    return packets


def ingest_pcap_to_states(
    pcap_path: str | Path,
    window_duration_s: float = 10.0,
    session_id: str | None = None,
    tshark_path: str | None = None,
    bpf_filter: str | None = None,
) -> List[NetworkState]:
    """Ingest an offline PCAP file and aggregate into causal 10-second NetworkState objects."""
    pcap_file = Path(pcap_path)
    if session_id is None:
        session_id = f"pcap_{pcap_file.stem}"

    packets = read_packets_from_pcap(
        pcap_path=pcap_file,
        tshark_path=tshark_path,
        bpf_filter=bpf_filter,
    )

    if not packets:
        return []

    # Sort packets strictly by timestamp to ensure causal ordering
    packets.sort(key=lambda p: p.timestamp)
    t0 = packets[0].timestamp
    t_end = packets[-1].timestamp
    total_span = t_end - t0
    n_windows = int(max(1, int(total_span / window_duration_s) + 1))

    windowed_bins = partition_packets_into_windows(
        packets,
        window_duration_s=window_duration_s,
        start_time=t0,
    )

    states: List[NetworkState] = []
    for w_idx in range(n_windows):
        win_start_epoch = t0 + w_idx * window_duration_s
        win_end_epoch = win_start_epoch + window_duration_s
        dt_start = datetime.fromtimestamp(win_start_epoch, tz=timezone.utc)
        dt_end = datetime.fromtimestamp(win_end_epoch, tz=timezone.utc)

        win_packets = windowed_bins.get(w_idx, [])
        state = build_network_state_from_packets(
            packets=win_packets,
            start_time=dt_start,
            end_time=dt_end,
            window_index=w_idx,
            session_id=session_id,
            window_duration_s=window_duration_s,
        )
        states.append(state)

    return states


def export_states_to_jsonl(
    states: Sequence[NetworkState],
    output_path: str | Path,
) -> None:
    """Save NetworkState sequence to .states.jsonl format matching repository artifacts."""
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        for s in states:
            record = {
                "window_id": s.window_id,
                "timestamp_start": s.timestamp_start.isoformat(),
                "timestamp_end": s.timestamp_end.isoformat(),
                "window_duration_s": s.window_duration_s,
                "flow_count": s.flow_count,
                "byte_rate": s.byte_rate,
                "packet_rate": s.packet_rate,
                "mean_flow_duration": s.mean_flow_duration,
                "src_ip_diversity": s.src_ip_diversity,
                "dst_ip_diversity": s.dst_ip_diversity,
                "src_port_diversity": s.src_port_diversity,
                "dst_port_diversity": s.dst_port_diversity,
                "fan_out": s.fan_out,
                "internal_ratio": s.internal_ratio,
                "east_west_count": s.east_west_count,
                "syn_count": s.syn_count,
                "ack_count": s.ack_count,
                "rst_count": s.rst_count,
                "syn_ratio": s.syn_ratio,
                "rst_ratio": s.rst_ratio,
                "iat_mean": s.iat_mean,
                "iat_std": s.iat_std,
                "iat_skew": s.iat_skew,
                "pkt_size_mean": s.pkt_size_mean,
                "pkt_size_std": s.pkt_size_std,
                "byte_variance": s.byte_variance,
                "ttl_mean": s.ttl_mean,
                "ttl_variance": s.ttl_variance,
                "tcp_window_mean": s.tcp_window_mean,
                "fragment_count": s.fragment_count,
                "retransmit_count": s.retransmit_count,
                "payload_size_mean": s.payload_size_mean,
                "source": s.source.value,
                "data_quality": s.data_quality,
                "is_empty": s.is_empty,
                "gap_before": s.gap_before,
                "gap_after": s.gap_after,
                "session_id": s.session_id,
                "provenance_hash": s.provenance_hash,
                "feature_availability": {
                    k: v.value for k, v in s.feature_availability.items()
                },
            }
            f.write(json.dumps(record) + "\n")
