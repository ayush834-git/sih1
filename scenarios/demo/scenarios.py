"""Deterministic Scenario Definitions for Controlled Replay & Demo (SIH 26153)."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Mapping, Sequence

from core.contracts import (
    FeatureAvailability,
    NetworkState,
    Source,
)
from eval.dataset import CSV_AVAILABLE_FEATURES


def create_demo_state(
    window_index: int,
    start_time: datetime,
    dst_port_diversity: int = 2,
    flow_count: int = 10,
    byte_rate: float = 1000.0,
    packet_rate: float = 20.0,
    syn_ratio: float = 0.05,
    rst_ratio: float = 0.02,
    iat_mean: float = 1.0,
    iat_std: float = 0.5,
    pkt_size_mean: float = 100.0,
    session_id: str = "demo-session-1",
) -> NetworkState:
    """Create a validated, schema-compliant NetworkState for demo replay."""
    t_start = start_time + timedelta(seconds=10 * window_index)
    t_end = t_start + timedelta(seconds=10)
    
    avail = {f: FeatureAvailability.AVAILABLE for f in CSV_AVAILABLE_FEATURES}
    avail["fan_out"] = FeatureAvailability.UNAVAILABLE
    avail["src_ip_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["dst_ip_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["src_port_diversity"] = FeatureAvailability.UNAVAILABLE
    avail["internal_ratio"] = FeatureAvailability.UNAVAILABLE
    avail["east_west_count"] = FeatureAvailability.UNAVAILABLE
    
    return NetworkState(
        window_id=f"demo_w{window_index:03d}_{t_start.strftime('%H%M%S')}_10s",
        timestamp_start=t_start,
        timestamp_end=t_end,
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
        session_id=session_id,
        provenance_hash="d" * 64,
        feature_availability=avail,
    )


def get_demo_scenario_states(scenario_name: str, start_time: datetime | None = None) -> list[NetworkState]:
    """
    Returns a sequence of NetworkState objects for the requested scenario.
    No labels or attack metadata enter the states.
    """
    t0 = start_time or datetime(2018, 3, 1, 15, 0, 0)
    
    if scenario_name == "demo_recon_15s":
        # 16 consecutive logical windows (T0 to T15)
        # History (w0..w4): Baseline normal traffic to populate AR(5) history buffer
        states = [
            create_demo_state(0, t0, dst_port_diversity=2, flow_count=12, byte_rate=1500.0),
            create_demo_state(1, t0, dst_port_diversity=3, flow_count=14, byte_rate=1600.0),
            create_demo_state(2, t0, dst_port_diversity=2, flow_count=11, byte_rate=1400.0),
            create_demo_state(3, t0, dst_port_diversity=3, flow_count=15, byte_rate=1550.0),
            create_demo_state(4, t0, dst_port_diversity=2, flow_count=12, byte_rate=1500.0),
            # T1: Subtle deviation
            create_demo_state(5, t0, dst_port_diversity=6, flow_count=25, byte_rate=2500.0, syn_ratio=0.15),
            # T2-T7: Port exploration begins & accelerates
            create_demo_state(6, t0, dst_port_diversity=16, flow_count=45, byte_rate=4500.0, syn_ratio=0.25),
            create_demo_state(7, t0, dst_port_diversity=24, flow_count=65, byte_rate=6000.0, syn_ratio=0.32),
            create_demo_state(8, t0, dst_port_diversity=32, flow_count=80, byte_rate=7500.0, syn_ratio=0.38),
            # T8-T11: Telemetry observation contradicts forecast (probe halts abruptly)
            create_demo_state(9, t0, dst_port_diversity=14, flow_count=35, byte_rate=3000.0, syn_ratio=0.12),
            create_demo_state(10, t0, dst_port_diversity=5, flow_count=18, byte_rate=1800.0, syn_ratio=0.08),
            create_demo_state(11, t0, dst_port_diversity=3, flow_count=14, byte_rate=1500.0, syn_ratio=0.05),
            # T12-T15: Returns to baseline
            create_demo_state(12, t0, dst_port_diversity=2, flow_count=12, byte_rate=1450.0),
            create_demo_state(13, t0, dst_port_diversity=2, flow_count=11, byte_rate=1400.0),
            create_demo_state(14, t0, dst_port_diversity=3, flow_count=13, byte_rate=1500.0),
            create_demo_state(15, t0, dst_port_diversity=2, flow_count=12, byte_rate=1480.0),
        ]
        return states

    elif scenario_name == "demo_recon":
        # Sustained port scanning attack progression
        states = [
            create_demo_state(0, t0, dst_port_diversity=2, flow_count=10),
            create_demo_state(1, t0, dst_port_diversity=2, flow_count=12),
            create_demo_state(2, t0, dst_port_diversity=3, flow_count=15),
            create_demo_state(3, t0, dst_port_diversity=3, flow_count=14),
            create_demo_state(4, t0, dst_port_diversity=4, flow_count=18),
            create_demo_state(5, t0, dst_port_diversity=12, flow_count=35, syn_ratio=0.20),
            create_demo_state(6, t0, dst_port_diversity=22, flow_count=60, syn_ratio=0.30),
            create_demo_state(7, t0, dst_port_diversity=35, flow_count=90, syn_ratio=0.40),
            create_demo_state(8, t0, dst_port_diversity=48, flow_count=120, syn_ratio=0.45),
            create_demo_state(9, t0, dst_port_diversity=60, flow_count=150, syn_ratio=0.50),
        ]
        return states

    elif scenario_name == "demo_dos":
        # High-volume connection flooding progression
        states = [
            create_demo_state(0, t0, flow_count=15, packet_rate=30.0, rst_ratio=0.01),
            create_demo_state(1, t0, flow_count=18, packet_rate=35.0, rst_ratio=0.02),
            create_demo_state(2, t0, flow_count=20, packet_rate=40.0, rst_ratio=0.01),
            create_demo_state(3, t0, flow_count=25, packet_rate=50.0, rst_ratio=0.02),
            create_demo_state(4, t0, flow_count=30, packet_rate=60.0, rst_ratio=0.03),
            create_demo_state(5, t0, flow_count=85, packet_rate=250.0, rst_ratio=0.15, syn_ratio=0.30),
            create_demo_state(6, t0, flow_count=180, packet_rate=600.0, rst_ratio=0.25, syn_ratio=0.40),
            create_demo_state(7, t0, flow_count=320, packet_rate=1200.0, rst_ratio=0.35, syn_ratio=0.50),
            create_demo_state(8, t0, flow_count=450, packet_rate=1800.0, rst_ratio=0.40, syn_ratio=0.55),
            create_demo_state(9, t0, flow_count=500, packet_rate=2000.0, rst_ratio=0.42, syn_ratio=0.60),
        ]
        return states

    elif scenario_name == "demo_exfiltration":
        # Heavy outbound byte transfer progression
        states = [
            create_demo_state(0, t0, byte_rate=2000.0, pkt_size_mean=120.0),
            create_demo_state(1, t0, byte_rate=2500.0, pkt_size_mean=130.0),
            create_demo_state(2, t0, byte_rate=2200.0, pkt_size_mean=125.0),
            create_demo_state(3, t0, byte_rate=3000.0, pkt_size_mean=140.0),
            create_demo_state(4, t0, byte_rate=3500.0, pkt_size_mean=150.0),
            create_demo_state(5, t0, byte_rate=30000.0, pkt_size_mean=350.0),
            create_demo_state(6, t0, byte_rate=85000.0, pkt_size_mean=500.0),
            create_demo_state(7, t0, byte_rate=180000.0, pkt_size_mean=700.0),
            create_demo_state(8, t0, byte_rate=320000.0, pkt_size_mean=850.0),
            create_demo_state(9, t0, byte_rate=450000.0, pkt_size_mean=920.0),
        ]
        return states

    elif scenario_name == "demo_ambiguous":
        # Mild mixed noisy traffic
        states = [
            create_demo_state(0, t0, dst_port_diversity=3, flow_count=15, byte_rate=2000.0),
            create_demo_state(1, t0, dst_port_diversity=4, flow_count=18, byte_rate=2500.0),
            create_demo_state(2, t0, dst_port_diversity=5, flow_count=20, byte_rate=3000.0),
            create_demo_state(3, t0, dst_port_diversity=6, flow_count=22, byte_rate=3200.0),
            create_demo_state(4, t0, dst_port_diversity=7, flow_count=25, byte_rate=4000.0),
            create_demo_state(5, t0, dst_port_diversity=8, flow_count=30, byte_rate=15000.0, syn_ratio=0.12),
            create_demo_state(6, t0, dst_port_diversity=9, flow_count=32, byte_rate=25000.0, syn_ratio=0.15),
            create_demo_state(7, t0, dst_port_diversity=8, flow_count=28, byte_rate=20000.0, syn_ratio=0.14),
            create_demo_state(8, t0, dst_port_diversity=6, flow_count=22, byte_rate=12000.0, syn_ratio=0.10),
            create_demo_state(9, t0, dst_port_diversity=4, flow_count=18, byte_rate=5000.0, syn_ratio=0.06),
        ]
        return states

    else:
        raise ValueError(f"Unknown scenario: {scenario_name}")
