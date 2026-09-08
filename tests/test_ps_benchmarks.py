"""Comprehensive unit and integration tests for PS 26153 compliance features and benchmarks."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

from core.contracts import FeatureAvailability, NetworkState, Source
from eval.dataset import CSV_AVAILABLE_FEATURES, TransitionSample
from eval.labels import (
    AttackInterval,
    STAGE_BENIGN,
    STAGE_IMPACT,
    STAGE_INFILTRATION,
    STAGE_LATERAL_EXFIL,
    STAGE_RECONNAISSANCE,
    TRANSITION_ATTACK_ACTIVE,
    TRANSITION_ATTACK_ONSET,
    TRANSITION_STEADY_BENIGN,
    annotate_transitions,
    is_timestamp_in_attack,
)
from eval.progression_probability import (
    CalibrationMetrics,
    ProgressionProbabilityModel,
    compute_ece,
)
from runtime.live.flow_accumulator import FlowAccumulator, FlowRecord
from runtime.live.packet_parser import ParsedPacket, parse_tshark_line
from runtime.live.state_builder import build_network_state_from_packets


# 1. Flow-level feature tests
def test_flow_record_extended_features() -> None:
    """Test bidirectional ratios, extended IAT, and all TCP flag statistics."""
    ep1 = ("127.0.0.1", 8765)
    ep2 = ("127.0.0.1", 50000)
    flow = FlowRecord(
        flow_key=(ep1, ep2, 6),
        initiator_src_ip="127.0.0.1",
        initiator_src_port=50000,
        initiator_dst_ip="127.0.0.1",
        initiator_dst_port=8765,
        protocol=6,
        start_time=100.0,
        last_time=102.0,
        fwd_packets=10,
        bwd_packets=5,
        fwd_bytes=1000,
        bwd_bytes=500,
        syn_count=1,
        ack_count=15,
        rst_count=0,
        fin_count=1,
        psh_count=4,
        urg_count=2,
        retransmit_count=1,
        packet_timestamps=[100.0, 100.5, 101.0, 101.5, 102.0],
        packet_lengths=[100, 200, 100, 50, 150],
    )

    # Bidirectional ratios
    assert flow.total_packets == 15
    assert flow.total_bytes == 1500
    assert flow.duration_s == 2.0
    assert flow.fwd_bwd_packet_ratio == 2.0
    assert flow.fwd_bwd_byte_ratio == 2.0
    assert abs(flow.fwd_packet_ratio - (10.0 / 15.0)) < 1e-6
    assert abs(flow.bwd_packet_ratio - (5.0 / 15.0)) < 1e-6
    assert abs(flow.fwd_byte_ratio - (1000.0 / 1500.0)) < 1e-6
    assert abs(flow.bwd_byte_ratio - (500.0 / 1500.0)) < 1e-6

    # Extended IAT stats
    mean_iat, std_iat, max_iat, var_iat = flow.compute_extended_iat_stats()
    assert abs(mean_iat - 0.5) < 1e-6
    assert abs(max_iat - 0.5) < 1e-6

    # Extended packet length stats
    pkt_mean, pkt_std, pkt_max, pkt_min = flow.compute_extended_pkt_len_stats()
    assert pkt_max == 200.0
    assert pkt_min == 50.0

    # Flow features export
    feats = flow.get_flow_features()
    assert feats["duration_s"] == 2.0
    assert feats["psh_count"] == 4.0
    assert feats["urg_count"] == 2.0
    assert feats["retransmit_count"] == 1.0


# 2. Packet-level feature parsing tests
def test_packet_parser_extended_fields() -> None:
    """Test extraction of URG, IP fragment flags, and retransmission markers."""
    # Synthetic tab-delimited TShark line with 20 fields
    tshark_line = (
        "1519782000.123456\t127.0.0.1\t127.0.0.1\t54321\t8765\t6\t128\t64\t"
        "1\t1\t0\t0\t1\t0x0032\t64\t65535\t1\t1\t0\t1"
    )
    pkt = parse_tshark_line(tshark_line)
    assert pkt is not None
    assert pkt.timestamp == 1519782000.123456
    assert pkt.src_port == 54321
    assert pkt.dst_port == 8765
    assert pkt.syn is True
    assert pkt.ack is True
    assert pkt.psh is True
    assert pkt.urg is True
    assert pkt.is_fragment is True
    assert pkt.is_retransmission is True


# 3. State builder packet attributes tests
def test_state_builder_packet_attributes() -> None:
    """Test that NetworkState populates fragment_count, retransmit_count, and TTL variance."""
    now_epoch = 1519782000.0
    pkts = [
        ParsedPacket(
            timestamp=now_epoch + 1.0,
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            src_port=50000,
            dst_port=8765,
            protocol=6,
            frame_len=100,
            payload_len=60,
            syn=True,
            ack=False,
            rst=False,
            fin=False,
            psh=False,
            raw_flags="0x0002",
            ttl=64,
            window_size=65535,
            packet_hash="hash1",
            urg=False,
            is_fragment=True,
            is_retransmission=False,
        ),
        ParsedPacket(
            timestamp=now_epoch + 2.0,
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            src_port=50000,
            dst_port=8765,
            protocol=6,
            frame_len=100,
            payload_len=60,
            syn=False,
            ack=True,
            rst=False,
            fin=False,
            psh=False,
            raw_flags="0x0010",
            ttl=60,
            window_size=65535,
            packet_hash="hash2",
            urg=False,
            is_fragment=False,
            is_retransmission=True,
        ),
    ]

    dt_start = datetime.fromtimestamp(now_epoch, tz=timezone.utc)
    dt_end = datetime.fromtimestamp(now_epoch + 10.0, tz=timezone.utc)

    state = build_network_state_from_packets(
        packets=pkts,
        start_time=dt_start,
        end_time=dt_end,
        window_index=0,
    )

    assert state.flow_count == 1
    assert state.fragment_count == 1
    assert state.retransmit_count == 1
    assert state.ttl_mean == 62.0
    assert state.ttl_variance == 4.0
    assert state.tcp_window_mean == 65535.0
    assert state.payload_size_mean == 60.0


# 4. Supervised labels tests
def test_supervised_labels_annotation() -> None:
    """Test transition annotation with attack intervals and MITRE stage mapping."""
    test_intervals = [
        AttackInterval(
            interval_id="test-block",
            attack_family="Infiltration",
            start_time=datetime(2026, 1, 1, 10, 0, 0),
            end_time=datetime(2026, 1, 1, 10, 30, 0),
            recon_duration_s=300.0,
        )
    ]

    # Check timestamps
    in_att, iv = is_timestamp_in_attack(datetime(2026, 1, 1, 10, 5, 0), test_intervals)
    assert in_att is True
    assert iv is not None and iv.interval_id == "test-block"

    in_att_before, _ = is_timestamp_in_attack(datetime(2026, 1, 1, 9, 59, 50), test_intervals)
    assert in_att_before is False

    # Synthetic transitions around onset
    samples = [
        TransitionSample(
            sample_id="s1",
            target_state_id="w1",
            target_start=datetime(2026, 1, 1, 9, 59, 50),
            session_id="sess1",
            feature_names=tuple(CSV_AVAILABLE_FEATURES),
            history_states=tuple([{"flow_count": 10.0}] * 6),
            current_state={"flow_count": 10.0},
            next_state={"flow_count": 10.0},
            delta={"flow_count": 0.0},
            history_deltas=tuple([{"flow_count": 0.0}] * 5),
        ),
        TransitionSample(
            sample_id="s2",
            target_state_id="w2",
            target_start=datetime(2026, 1, 1, 10, 0, 0),  # Onset!
            session_id="sess1",
            feature_names=tuple(CSV_AVAILABLE_FEATURES),
            history_states=tuple([{"flow_count": 10.0}] * 6),
            current_state={"flow_count": 10.0},
            next_state={"flow_count": 50.0},
            delta={"flow_count": 40.0},
            history_deltas=tuple([{"flow_count": 0.0}] * 5),
        ),
        TransitionSample(
            sample_id="s3",
            target_state_id="w3",
            target_start=datetime(2026, 1, 1, 10, 0, 10),
            session_id="sess1",
            feature_names=tuple(CSV_AVAILABLE_FEATURES),
            history_states=tuple([{"flow_count": 10.0}] * 6),
            current_state={"flow_count": 50.0},
            next_state={"flow_count": 60.0},
            delta={"flow_count": 10.0},
            history_deltas=tuple([{"flow_count": 40.0}] * 5),
        ),
    ]

    labeled = annotate_transitions(samples, test_intervals)
    assert len(labeled) == 3

    assert labeled[0].transition_type == TRANSITION_STEADY_BENIGN
    assert labeled[0].current_is_attack == 0
    assert labeled[0].next_is_attack == 0

    assert labeled[1].transition_type == TRANSITION_ATTACK_ONSET
    assert labeled[1].current_is_attack == 0
    assert labeled[1].next_is_attack == 1

    assert labeled[2].transition_type == TRANSITION_ATTACK_ACTIVE
    assert labeled[2].current_is_attack == 1
    assert labeled[2].next_is_attack == 1

    # Verify official MITRE ATT&CK taxonomy mapping
    from eval.labels import MITRE_ATTACK_TAXONOMY
    assert MITRE_ATTACK_TAXONOMY[STAGE_RECONNAISSANCE]["technique_id"] == "T1595"
    assert MITRE_ATTACK_TAXONOMY[STAGE_RECONNAISSANCE]["technique_name"] == "Active Scanning"
    assert MITRE_ATTACK_TAXONOMY[STAGE_INFILTRATION]["technique_id"] == "T1190"
    assert MITRE_ATTACK_TAXONOMY[STAGE_INFILTRATION]["technique_name"] == "Exploit Public-Facing Application"
    assert "T1021" in MITRE_ATTACK_TAXONOMY[STAGE_LATERAL_EXFIL]["technique_id"]
    assert "T1048" in MITRE_ATTACK_TAXONOMY[STAGE_LATERAL_EXFIL]["technique_id"]
    assert MITRE_ATTACK_TAXONOMY[STAGE_IMPACT]["technique_id"] == "T1499"
    assert MITRE_ATTACK_TAXONOMY[STAGE_IMPACT]["technique_name"] == "Endpoint DoS"



# 5. Calibrated progression probability tests
def test_progression_probability_calibration() -> None:
    """Test training and calibration of ProgressionProbabilityModel on synthetic data."""
    rng = np.random.default_rng(42)
    n_train = 200
    n_val = 100
    n_test = 100
    n_feats = len(CSV_AVAILABLE_FEATURES)

    # Synthetic normal vs anomalous features
    X_tr = rng.normal(loc=10.0, scale=2.0, size=(n_train, n_feats))
    y_tr = np.zeros(n_train, dtype=int)
    # Add attack patterns
    X_tr[:50, 0] += 50.0
    y_tr[:50] = 1

    X_va = rng.normal(loc=10.0, scale=2.0, size=(n_val, n_feats))
    y_val = np.zeros(n_val, dtype=int)
    X_va[:25, 0] += 50.0
    y_val[:25] = 1

    X_te = rng.normal(loc=10.0, scale=2.0, size=(n_test, n_feats))
    y_te = np.zeros(n_test, dtype=int)
    X_te[:30, 0] += 50.0
    y_te[:30] = 1

    model = ProgressionProbabilityModel(
        feature_names=CSV_AVAILABLE_FEATURES,
        horizon_steps=3,
        calibration_method="sigmoid",
    )
    model.fit(X_tr, y_tr, X_val=X_va, y_val=y_val)

    probs = model.predict_proba(X_te)
    assert len(probs) == n_test
    assert np.all(probs >= 0.0) and np.all(probs <= 1.0)

    # Verify calibration metrics
    metrics = model.evaluate_on_test(X_te, y_te)
    assert isinstance(metrics, CalibrationMetrics)
    assert 0.0 <= metrics.brier_score <= 1.0
    assert 0.0 <= metrics.expected_calibration_error <= 1.0
    assert metrics.roc_auc >= 0.85  # Strong discrimination on synthetic anomaly


# 6. Benchmark and Unseen Generalization Artifacts Existence
def test_benchmark_artifacts_exist() -> None:
    """Verify that the strict LR benchmark artifacts were generated."""
    bench_dir = Path("artifacts/experiments/logistic_regression_benchmark_v1")
    assert (bench_dir / "benchmark_results.json").exists()
    assert (bench_dir / "benchmark_comparison.csv").exists()
    assert (bench_dir / "manifest.json").exists()

    with open(bench_dir / "benchmark_results.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "models_evaluated" in data
    assert len(data["models_evaluated"]) == 5
    assert data["metadata"]["total_transitions"] == 6727


def test_unseen_attack_artifacts_exist() -> None:
    """Verify that the unseen attack generalization artifacts were generated."""
    unseen_dir = Path("artifacts/experiments/unseen_attack_generalization_v1")
    assert (unseen_dir / "generalization_results.json").exists()
    assert (unseen_dir / "unseen_comparison.csv").exists()
    assert (unseen_dir / "manifest.json").exists()

    with open(unseen_dir / "generalization_results.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "comparison" in data
    assert len(data["comparison"]) == 2


# 7. End-to-end Ingestion to Inference Tests (PCAP + CSV)
def test_end_to_end_pcap_to_ar5_inference() -> None:
    """Verify PCAP -> packet parser -> NetworkState -> authoritative AR(5) inference."""
    from ingest.pcap_ingest import ingest_pcap_to_states
    from runtime.train_authoritative_model import load_ar_model
    from scenarios.demo.engine import LiveDemoEngine

    pcap_path = Path("artifacts/scratch/test_pipeline.pcap")
    if not pcap_path.exists():
        pytest.skip("Test PCAP file not present")

    # Ingest PCAP to causal NetworkState sequence
    states = ingest_pcap_to_states(pcap_path, window_duration_s=10.0)
    assert len(states) >= 1
    assert states[0].source == Source.PCAP

    # Load authoritative AR(5) model
    model_dir = Path("artifacts/models/ar5_authoritative")
    ar_model, scales = load_ar_model(model_dir)
    engine = LiveDemoEngine(ar_model=ar_model, scales=scales)

    # Perform streaming inference
    events = list(engine.stream_scenario(states))
    assert len(events) == len(states)
    for evt in events:
        assert evt.current_state_summary is not None
        assert evt.predicted_deltas_h1 is not None
        assert evt.current_risk_score >= 0.0


def test_end_to_end_csv_to_ar5_inference(tmp_path: Path) -> None:
    """Verify CSV -> CIC parser -> NetworkState -> authoritative AR(5) inference."""
    import csv
    from ingest.cic_flow import build_states
    from runtime.train_authoritative_model import load_ar_model
    from scenarios.demo.engine import LiveDemoEngine

    # Synthesize a minimal valid CIC CSV with 2 time windows
    csv_file = tmp_path / "test_flows.csv"
    headers = [
        "Timestamp", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
        "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Flow Byts/s", "Flow Pkts/s",
        "Flow IAT Mean", "Flow IAT Std", "SYN Flag Cnt", "ACK Flag Cnt",
        "RST Flag Cnt", "Pkt Len Mean", "Pkt Len Std", "Dst Port", "Protocol",
    ]
    rows = [
        # Window 1: 08:00:00 - 08:00:10
        ["28/02/2018 08:00:01", "1000", "5", "5", "500", "500", "100.0", "10.0", "100.0", "10.0", "1", "1", "0", "100.0", "10.0", "80", "6"],
        ["28/02/2018 08:00:05", "2000", "8", "6", "800", "600", "150.0", "12.0", "120.0", "15.0", "1", "2", "0", "100.0", "12.0", "443", "6"],
        # Window 2: 08:00:10 - 08:00:20
        ["28/02/2018 08:00:12", "1500", "4", "4", "400", "400", "90.0", "8.0", "80.0", "5.0", "0", "1", "0", "90.0", "8.0", "80", "6"],
    ]

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    # Ingest CSV to causal NetworkState sequence
    states, stats = build_states(csv_file)
    assert len(states) == 2
    assert stats.rows_read == 3
    assert stats.rows_retained == 3
    assert states[0].source == Source.CSV

    # Load authoritative AR(5) model
    model_dir = Path("artifacts/models/ar5_authoritative")
    ar_model, scales = load_ar_model(model_dir)
    engine = LiveDemoEngine(ar_model=ar_model, scales=scales)

    # Perform streaming inference
    events = list(engine.stream_scenario(states))
    assert len(events) == 2
    for evt in events:
        assert evt.current_state_summary is not None
        assert evt.predicted_deltas_h1 is not None
        assert evt.current_risk_score >= 0.0

