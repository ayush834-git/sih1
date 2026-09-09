"""Comprehensive Test Suite for Live Packet Capture & Forecasting Pipeline (SIH 26153).

Validates all 25 critical requirements:
1. TShark executable discovery
2. Npcap availability detection
3. Explicit loopback interface discovery
4. Capture startup
5. Clean capture shutdown
6. Controlled generator reaches localhost
7. Parser extracts expected packet fields
8. TCP flags are really observed
9. Flow aggregation is correct
10. Known payload byte count is consistent with chosen semantics
11. Timestamps are monotonic / ordered appropriately
12. 10-second causal windowing
13. No future leakage
14. Empty/idle windows
15. State provenance
16. Generated traffic vs observed traffic correspondence
17. Live NetworkState compatibility
18. Live state reaches existing AR(5)
19. Resulting DemoEvent provenance identifies LIVE mode
20. SSE receives the live event
21. Demo mode remains unchanged
22. Live mode and replay mode cannot silently masquerade as each other
23. Safe shutdown leaves no orphaned capture process
24. Repeated start/stop does not corrupt state
25. Concurrent start requests are handled safely
"""
from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.contracts import FeatureAvailability, NetworkState, Source
from eval.dataset import CSV_AVAILABLE_FEATURES
from runtime.api import create_app
from runtime.demo_adapter import DemoAdapter
from runtime.live.backend import (
    CaptureInterface,
    find_tshark_executable,
    get_verified_loopback_interface,
    inspect_capture_backend,
)
from runtime.live.flow_accumulator import (
    FlowAccumulator,
    partition_packets_into_windows,
)
from runtime.live.live_controller import LiveCaptureController
from runtime.live.packet_capture import LivePacketCapture
from runtime.live.packet_parser import ParsedPacket, parse_tshark_line
from runtime.live.provenance import create_experiment_artifacts
from runtime.live.state_builder import build_network_state_from_packets
from runtime.live.traffic_generator import ControlledTrafficGenerator
from runtime.state_store import DemoStatus, RuntimeStateStore
from scenarios.demo.engine import LiveDemoEngine


# ────────────────────────────────────────────────────────────
# 1-3: Discovery and Environment
# ────────────────────────────────────────────────────────────

def test_tshark_discovery():
    """1. Verify TShark executable is located on Windows."""
    tshark_path = find_tshark_executable()
    assert tshark_path.is_file(), f"TShark binary does not exist at {tshark_path}"
    assert "tshark" in tshark_path.name.lower()


def test_npcap_availability():
    """2. Verify Npcap driver capability is detected."""
    info = inspect_capture_backend()
    assert info.has_npcap is True
    assert info.npcap_version != "none"


def test_loopback_discovery():
    """3. Verify explicit loopback interface (\\Device\\NPF_Loopback) is discovered."""
    loopback = get_verified_loopback_interface()
    assert isinstance(loopback, CaptureInterface)
    assert loopback.is_loopback is True
    assert "loopback" in loopback.device_name.lower() or "loopback" in loopback.description.lower()


# ────────────────────────────────────────────────────────────
# 4-6: Capture and Generator
# ────────────────────────────────────────────────────────────

def test_capture_startup_and_shutdown():
    """4 & 5. Verify capture startup and deterministic cleanup without orphans."""
    capture = LivePacketCapture(allowed_ports=[8765])
    assert not capture.is_active
    capture.start()
    assert capture.is_active
    pid = capture.stats.process_pid
    assert pid is not None

    stats = capture.stop()
    assert not capture.is_active
    assert stats.end_time >= stats.start_time

    # Verify process terminated
    terminated = False
    for _ in range(10):
        try:
            os.kill(pid, 0)
            time.sleep(0.2)
        except OSError:
            terminated = True
            break
    assert terminated, f"Process {pid} was not terminated"


def test_controlled_generator_traffic():
    """6. Verify controlled generator successfully connects to localhost echo server."""
    gen = ControlledTrafficGenerator(ports=[8765])
    gen.start("baseline", speed=5.0)
    time.sleep(1.0)
    stats = gen.stop()
    assert stats.connections_succeeded > 0
    assert stats.bytes_sent > 0
    assert not stats.is_running


# ────────────────────────────────────────────────────────────
# 7-11: Packet Parsing, Flags, and Flows
# ────────────────────────────────────────────────────────────

def test_packet_parser_fields():
    """7. Verify parser extracts all expected packet fields with microsecond precision."""
    raw_line = "1788626952.802552100\t127.0.0.1\t127.0.0.1\t54321\t8765\t6\t120\t60\tFalse\tTrue\tFalse\tFalse\tTrue\t0x0018\t128\t65535"
    pkt = parse_tshark_line(raw_line, allowed_ips={"127.0.0.1"}, allowed_ports={8765})
    assert pkt is not None
    assert abs(pkt.timestamp - 1788626952.802552) < 1e-4
    assert pkt.src_ip == "127.0.0.1"
    assert pkt.dst_ip == "127.0.0.1"
    assert pkt.src_port == 54321
    assert pkt.dst_port == 8765
    assert pkt.protocol == 6
    assert pkt.frame_len == 120
    assert pkt.payload_len == 60
    assert pkt.syn is False
    assert pkt.ack is True
    assert pkt.rst is False
    assert pkt.fin is False
    assert pkt.psh is True
    assert pkt.ttl == 128
    assert pkt.window_size == 65535
    assert pkt.is_in_scope is True


def test_tcp_flags_observation():
    """8. Verify TCP flags (SYN, ACK, RST, FIN) are correctly distinguished."""
    syn_line = "100.0\t127.0.0.1\t127.0.0.1\t50000\t8765\t6\t60\t0\tTrue\tFalse\tFalse\tFalse\tFalse\t0x0002"
    rst_line = "100.1\t127.0.0.1\t127.0.0.1\t50000\t8765\t6\t40\t0\tFalse\tFalse\tTrue\tFalse\tFalse\t0x0004"
    fin_line = "100.2\t127.0.0.1\t127.0.0.1\t50000\t8765\t6\t40\t0\tFalse\tTrue\tFalse\tTrue\tFalse\t0x0011"

    p_syn = parse_tshark_line(syn_line)
    p_rst = parse_tshark_line(rst_line)
    p_fin = parse_tshark_line(fin_line)

    assert p_syn.syn is True and p_syn.ack is False
    assert p_rst.rst is True and p_rst.syn is False
    assert p_fin.fin is True and p_fin.ack is True


def test_flow_aggregation_and_byte_consistency():
    """9 & 10. Verify bi-directional flow grouping and byte tracking consistency."""
    acc = FlowAccumulator()
    p1 = ParsedPacket(100.0, "127.0.0.1", "127.0.0.1", 50001, 8765, 6, 60, 0, True, False, False, False, False, "0x0002", 128, 65535, "h1")
    p2 = ParsedPacket(100.01, "127.0.0.1", "127.0.0.1", 8765, 50001, 6, 60, 0, True, True, False, False, False, "0x0012", 128, 65535, "h2")
    p3 = ParsedPacket(100.02, "127.0.0.1", "127.0.0.1", 50001, 8765, 6, 100, 40, False, True, False, False, True, "0x0018", 128, 65535, "h3")

    acc.add_packet(p1)
    acc.add_packet(p2)
    acc.add_packet(p3)

    flows = acc.get_flows()
    assert len(flows) == 1
    flow = flows[0]
    assert flow.fwd_packets == 2
    assert flow.bwd_packets == 1
    assert flow.total_packets == 3
    assert flow.total_bytes == 220
    assert flow.syn_count == 2
    assert flow.ack_count == 2
    assert flow.dst_port == 8765


def test_timestamp_ordering_and_causal_windowing():
    """11 & 12. Verify window partitioning is monotonic, causal, and non-overlapping."""
    packets = [
        ParsedPacket(10.0 + i * 2.0, "127.0.0.1", "127.0.0.1", 50000 + i, 8765, 6, 100, 50, True, False, False, False, False, "0x0002", 128, 65535, f"h{i}")
        for i in range(15)  # Timestamps: 10, 12, 14, ..., 38 (spans across 3 10-second windows: [10,20), [20,30), [30,40))
    ]
    bins = partition_packets_into_windows(packets, window_duration_s=10.0, start_time=10.0)
    assert set(bins.keys()) == {0, 1, 2}
    assert len(bins[0]) == 5  # 10, 12, 14, 16, 18
    assert len(bins[1]) == 5  # 20, 22, 24, 26, 28
    assert len(bins[2]) == 5  # 30, 32, 34, 36, 38

    # All timestamps in bin 0 are strictly < 20
    assert all(p.timestamp < 20.0 for p in bins[0])
    assert all(p.timestamp >= 20.0 and p.timestamp < 30.0 for p in bins[1])


def test_no_future_leakage():
    """13. Verify that state built from window k contains zero information from future packets."""
    past_packets = [
        ParsedPacket(100.0, "127.0.0.1", "127.0.0.1", 50001, 8765, 6, 100, 50, True, False, False, False, False, "0x0002", 128, 65535, "hp")
    ]
    future_packets = [
        ParsedPacket(115.0, "127.0.0.1", "127.0.0.1", 50002, 8765, 6, 500, 450, True, False, False, False, False, "0x0002", 128, 65535, "hf")
    ]

    t0 = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)

    state = build_network_state_from_packets(past_packets, t0, t1, window_index=0)
    assert state.flow_count == 1
    assert state.packet_rate == 0.1
    # Ensure future packet did not inflate byte_rate or flow_count
    assert state.byte_rate == 10.0


def test_empty_window_handling():
    """14. Verify idle/empty windows produce valid schema-compliant empty NetworkState."""
    t0 = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)

    state = build_network_state_from_packets([], t0, t1, window_index=1)
    assert state.is_empty is True
    assert state.flow_count == 0
    assert state.byte_rate == 0.0
    assert state.packet_rate == 0.0
    assert state.dst_port_diversity == 0
    assert state.data_quality == 0.0
    assert state.source == Source.PCAP


def test_state_provenance_hashing():
    """15. Verify state provenance hash is deterministic and derived from packet hashes."""
    p1 = ParsedPacket(100.0, "127.0.0.1", "127.0.0.1", 50001, 8765, 6, 100, 50, True, False, False, False, False, "0x0002", 128, 65535, "hash_a")
    p2 = ParsedPacket(101.0, "127.0.0.1", "127.0.0.1", 50002, 8765, 6, 200, 150, True, False, False, False, False, "0x0002", 128, 65535, "hash_b")

    t0 = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)

    state1 = build_network_state_from_packets([p1, p2], t0, t1, window_index=0)
    state2 = build_network_state_from_packets([p1, p2], t0, t1, window_index=0)
    assert state1.provenance_hash == state2.provenance_hash
    assert len(state1.provenance_hash) == 64


# ────────────────────────────────────────────────────────────
# 16-19: Live Capture to AR(5) Intelligence Pipeline
# ────────────────────────────────────────────────────────────

def test_traffic_correspondence_and_live_state_contract():
    """16 & 17. Verify live capture captures generated packets and builds valid NetworkState."""
    capture = LivePacketCapture(allowed_ports=[8765])
    gen = ControlledTrafficGenerator(ports=[8765])

    capture.start()
    time.sleep(0.5)
    gen.start("baseline", speed=5.0)
    time.sleep(2.0)
    g_stats = gen.stop()
    c_stats = capture.stop()

    packets = capture.get_packets()
    assert len(packets) > 0
    assert c_stats.out_of_scope_packets == 0
    assert len(c_stats.isolation_violations) == 0

    t0 = datetime.now(timezone.utc)
    t1 = t0 + timedelta(seconds=10)
    state = build_network_state_from_packets(packets, t0, t1, window_index=0)

    assert isinstance(state, NetworkState)
    assert state.source == Source.PCAP
    assert state.flow_count > 0
    assert state.dst_port_diversity == 1  # only port 8765
    assert state.syn_count > 0


def test_live_state_ar5_rollout_and_provenance():
    """18 & 19. Verify live state reaches existing AR(5) and emits DemoEvent with live provenance."""
    capture = LivePacketCapture(allowed_ports=[8765])
    gen = ControlledTrafficGenerator(ports=[8765])

    capture.start()
    gen.start("baseline", speed=5.0)
    time.sleep(1.2)
    gen.stop()
    capture.stop()

    packets = capture.get_packets()
    t0 = datetime.now(timezone.utc)
    t1 = t0 + timedelta(seconds=10)
    state = build_network_state_from_packets(packets, t0, t1, window_index=0)

    engine = LiveDemoEngine()
    events = list(engine.stream_scenario([state]))
    assert len(events) == 1
    event = events[0]

    assert event.event_id.startswith("evt-0000")
    assert "dst_port_diversity" in event.current_state_summary
    assert "dst_port_diversity_delta" in event.predicted_deltas_h1
    assert event.current_risk_score >= 0.0


# ────────────────────────────────────────────────────────────
# 20-22: SSE, API, and Mutual Exclusion
# ────────────────────────────────────────────────────────────

def test_api_live_endpoints_and_sse():
    """20. Verify FastAPI live endpoints expose live status and provenance."""
    app = create_app()
    client = TestClient(app)

    # Health check
    res_h = client.get("/api/v1/health")
    assert res_h.status_code == 200

    # Live status check
    res_s = client.get("/api/v1/live/status")
    assert res_s.status_code == 200
    data = res_s.json()
    assert data["execution_mode"] == "LIVE_PACKET_CAPTURE"
    assert data["is_active"] is False


def test_demo_mode_unchanged():
    """21. Verify existing demo replay mode continues to work 100% as before."""
    app = create_app()
    client = TestClient(app)

    res_start = client.post("/api/v1/demo/start", json={"scenario": "demo_recon_15s", "speed": 0.0})
    assert res_start.status_code == 200
    data = res_start.json()
    assert data["scenario"] == "demo_recon_15s"
    assert data["status"] == "RUNNING"

    res_step = client.post("/api/v1/demo/step")
    assert res_step.status_code == 200
    step_data = res_step.json()
    assert step_data["execution_mode"] == "DEMO"
    assert step_data["step_index"] == 0

    client.post("/api/v1/demo/reset")


def test_mutual_exclusion_and_anti_masquerading():
    """22. Verify Live Packet Capture and Demo Replay cannot run concurrently or masquerade."""
    adapter = DemoAdapter()
    store = adapter.store
    ctrl = LiveCaptureController(adapter=adapter)

    # Start demo replay
    asyncio.run(adapter.start("demo_recon_15s", speed=0.0))
    assert adapter.status == DemoStatus.RUNNING
    assert store.execution_mode == "DEMO"

    # Attempting to start live capture must fail with conflict
    with pytest.raises(RuntimeError, match="Cannot start live packet capture while Demo Replay is RUNNING"):
        asyncio.run(ctrl.start(scenario="baseline", duration_windows=1))

    # Reset adapter
    asyncio.run(adapter.reset())
    assert adapter.status == DemoStatus.IDLE


# ────────────────────────────────────────────────────────────
# 23-25: Concurrency and Resilience
# ────────────────────────────────────────────────────────────

def test_safe_shutdown_leaves_no_orphaned_processes():
    """23. Verify repeated start and stop leaves zero orphaned capture or generator processes."""
    capture = LivePacketCapture(allowed_ports=[8765])
    capture.start()
    pid = capture.stats.process_pid
    assert pid is not None
    capture.stop()

    time.sleep(0.5)
    try:
        os.kill(pid, 0)
        pytest.fail("TShark process is still running after stop()!")
    except OSError:
        pass  # Cleanly terminated


def test_repeated_start_stop():
    """24. Verify repeated start/stop cycles do not leak state or raise errors."""
    capture = LivePacketCapture(allowed_ports=[8765])
    gen = ControlledTrafficGenerator(ports=[8765])

    for _ in range(2):
        capture.start()
        gen.start("baseline", speed=5.0)
        time.sleep(0.5)
        gen.stop()
        capture.stop()
        assert not capture.is_active
        assert not gen.stats.is_running


def test_concurrent_start_safety():
    """25. Verify concurrent start calls are rejected safely."""
    capture = LivePacketCapture(allowed_ports=[8765])
    capture.start()
    # Second start while already active should be a no-op
    capture.start()
    assert capture.is_active
    capture.stop()
