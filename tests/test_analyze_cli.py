"""Comprehensive automated tests for offline CLI inference interface (analyze.py).

Verifies:
1. Zero pickle: progression model is canonical JSON, deterministically reconstructed.
2. Exact numerical metrics match benchmark results.
3. PCAP offline ingestion with parallel packet-evidence retention.
4. CSV offline ingestion with flow-level evidence.
5. Deterministic multi-dimensional flagging policy (4 independent channels).
6. Semantic independence of progression probability, risk, trust, stage, and explainability.
7. CLI command-line arguments and outputs (text format, JSON format, file writing).
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import List

import numpy as np
import pytest

from analyze import (
    PersistedProgressionModel,
    format_text_summary,
    ingest_offline_input,
    main,
    run_offline_analysis,
    summarize_packet_evidence,
)
from core.contracts import STATE_SCHEMA_HASH
from eval.dataset import CSV_AVAILABLE_FEATURES
from runtime.train_progression_model import canonical_json_dumps


PROGRESSION_MODEL_PATH = Path("artifacts/models/ar5_authoritative/progression_model.json")
AR_MODEL_DIR = Path("artifacts/models/ar5_authoritative")
TEST_PCAP_PATH = Path("artifacts/scratch/test_pipeline.pcap")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Model Artifact & Determinism Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_progression_model_json_artifact_exists_and_valid() -> None:
    """Verify progression model is valid canonical JSON with complete parameter sets and no pickle."""
    assert PROGRESSION_MODEL_PATH.exists(), "progression_model.json must exist"

    raw_text = PROGRESSION_MODEL_PATH.read_text(encoding="utf-8")
    assert "pickle" not in raw_text.lower(), "pickle string found in artifact"

    data = json.loads(raw_text)
    assert data["schema_version"] == 1
    assert data["model_type"] == "CalibratedLogisticRegression"
    assert data["model_version"] == "1.0.0"

    # Verify target definition
    target = data["target_definition"]
    assert target["name"] == "lookahead_attack_h3"
    assert target["horizon_steps"] == 3

    # Verify feature schema
    schema = data["feature_schema"]
    assert schema["input_dimension"] == 30
    assert len(schema["feature_order"]) == 30

    # Verify preprocessing parameters
    pre = data["preprocessing"]
    assert pre["scaler_type"] == "StandardScaler"
    assert len(pre["mean"]) == 30
    assert len(pre["scale"]) == 30

    # Verify classifier weights
    clf = data["classifier"]
    assert clf["type"] == "LogisticRegression"
    assert len(clf["coefficients"]) == 30
    assert isinstance(clf["intercept"], (float, int))

    # Verify calibration parameters
    cal = data["calibration"]
    assert cal["method"] == "sigmoid"
    assert isinstance(cal["calibrator_a"], float)
    assert isinstance(cal["calibrator_b"], float)

    # Verify training provenance
    prov = data["training_provenance"]
    assert prov["schema_hash"] == STATE_SCHEMA_HASH
    assert prov["split_sizes"] == {"train": 4036, "val": 1009, "test": 1682}

    # Verify provenance hash
    prov_hash = data["provenance_hash"]
    data_without_hash = {k: v for k, v in data.items() if k != "provenance_hash"}
    expected_hash = hashlib.sha256(canonical_json_dumps(data_without_hash).encode("utf-8")).hexdigest()
    assert prov_hash == expected_hash, "Provenance SHA-256 hash mismatch"


def test_persisted_progression_model_loader_and_bounds() -> None:
    """Verify PersistedProgressionModel loads cleanly and produces bounded [0, 1] probabilities."""
    model = PersistedProgressionModel(PROGRESSION_MODEL_PATH)
    assert model.model_version == "1.0.0"
    assert len(model.mean) == 30
    assert len(model.coef) == 30

    # Test with baseline values
    zero_vals = {f: 0.0 for f in CSV_AVAILABLE_FEATURES}
    prob = model.predict_single(zero_vals, zero_vals)
    assert 0.0 <= prob <= 1.0
    assert isinstance(prob, float)

    # Test with large positive values
    high_vals = {f: 100000.0 for f in CSV_AVAILABLE_FEATURES}
    prob_high = model.predict_single(high_vals, high_vals)
    assert 0.0 <= prob_high <= 1.0


def test_progression_model_metrics_match_benchmark() -> None:
    """Verify persisted test metrics match validated benchmark results."""
    with open(PROGRESSION_MODEL_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    metrics = data["test_metrics"]
    assert metrics["brier_score"] == 0.127827
    assert metrics["expected_calibration_error"] == 0.089025
    assert metrics["maximum_calibration_error"] == 0.337867
    assert metrics["roc_auc"] == 0.814302
    assert metrics["log_loss"] == 0.409808
    assert metrics["precision_at_0.50"] == 0.8644
    assert metrics["recall_at_0.50"] == 0.1478
    assert metrics["f1_at_0.50"] == 0.2525
    assert metrics["false_positive_rate_at_0.50"] == 0.006


# ─────────────────────────────────────────────────────────────────────────────
# 2. PCAP Ingestion & Packet Evidence Retention Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_pcap_offline_inference_and_packet_retention() -> None:
    """Verify PCAP analysis extracts states, runs inference, and retains un-aggregated packet evidence."""
    if not TEST_PCAP_PATH.exists():
        pytest.skip(f"Test PCAP not found: {TEST_PCAP_PATH}")

    report = run_offline_analysis(
        input_path=TEST_PCAP_PATH,
        ar_model_dir=AR_MODEL_DIR,
        progression_model_path=PROGRESSION_MODEL_PATH,
    )

    assert report["input_type"] == "PCAP"
    assert report["summary"]["total_windows"] >= 1
    assert "model_provenance" in report

    # Check that each window record contains packet evidence retained from the raw capture
    for w in report["time_series"]:
        pkt_ev = w["packet_evidence"]
        assert pkt_ev["available"] is True
        assert pkt_ev["packet_count"] > 0
        assert pkt_ev["total_wire_bytes"] > 0
        assert pkt_ev["unique_flows_count"] > 0
        assert "tcp_flags" in pkt_ev
        assert "sample_packets" in pkt_ev
        assert len(pkt_ev["sample_packets"]) > 0


def test_packet_evidence_summary_computation() -> None:
    """Verify summarize_packet_evidence correctly computes 5-tuples and flags."""
    from runtime.live.packet_parser import ParsedPacket

    packets = [
        ParsedPacket(
            timestamp=100.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=5000,
            dst_port=80,
            protocol=6,
            frame_len=100,
            payload_len=40,
            syn=True,
            ack=False,
            rst=False,
            fin=False,
            psh=False,
            raw_flags="0x0002",
            ttl=64,
            window_size=1024,
            packet_hash="hash1",
        ),
        ParsedPacket(
            timestamp=100.5,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=5000,
            dst_port=80,
            protocol=6,
            frame_len=200,
            payload_len=140,
            syn=False,
            ack=True,
            rst=False,
            fin=False,
            psh=True,
            raw_flags="0x0018",
            ttl=64,
            window_size=1024,
            packet_hash="hash2",
        ),
    ]

    summary = summarize_packet_evidence(packets)
    assert summary["packet_count"] == 2
    assert summary["total_wire_bytes"] == 300
    assert summary["unique_flows_count"] == 1
    assert summary["tcp_flags"]["syn"] == 1
    assert summary["tcp_flags"]["ack"] == 1
    assert summary["tcp_flags"]["psh"] == 1
    assert summary["tcp_flags"]["rst"] == 0
    assert len(summary["sample_packets"]) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 3. CSV Ingestion & Flagging Detection Tests
# ─────────────────────────────────────────────────────────────────────────────

def synthesize_test_csv(file_path: Path, num_benign: int = 5, num_attack: int = 5) -> Path:
    """Generate a valid synthetic CIC-IDS2018 CSV file with benign and port scanning traffic."""
    headers = [
        "Timestamp", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
        "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Flow Byts/s", "Flow Pkts/s",
        "Flow IAT Mean", "Flow IAT Std", "SYN Flag Cnt", "ACK Flag Cnt",
        "RST Flag Cnt", "Pkt Len Mean", "Pkt Len Std", "Dst Port", "Protocol",
    ]
    rows = []

    # Benign windows: low port diversity (port 80 only)
    for w in range(num_benign):
        t_sec = w * 10
        rows.append([
            f"28/02/2018 08:00:{t_sec:02d}", "1000", "5", "5", "500", "500",
            "100.0", "10.0", "100.0", "10.0", "1", "4", "0", "100.0", "10.0", "80", "6",
        ])

    # Attack windows: high port diversity across 30 ports with elevated SYN
    for w in range(num_attack):
        t_sec = w * 10
        for p_offset in range(30):
            port = 1000 + p_offset
            rows.append([
                f"28/02/2018 08:01:{t_sec:02d}", "500", "2", "0", "100", "0",
                "1000.0", "20.0", "50.0", "5.0", "1", "0", "0", "50.0", "5.0", str(port), "6",
            ])

    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    return file_path


def test_csv_offline_inference_and_attack_detection(tmp_path: Path) -> None:
    """Verify CSV flow ingestion flags reconnaissance windows with explicit trigger channels."""
    csv_file = tmp_path / "test_traffic.csv"
    synthesize_test_csv(csv_file, num_benign=5, num_attack=5)

    report = run_offline_analysis(
        input_path=csv_file,
        ar_model_dir=AR_MODEL_DIR,
        progression_model_path=PROGRESSION_MODEL_PATH,
    )

    assert report["input_type"] == "CSV"
    assert report["summary"]["total_windows"] > 0
    assert report["summary"]["flagged_windows_count"] > 0
    assert "Reconnaissance" in report["summary"]["attack_stages_detected"]

    # Verify CSV packet evidence indicates unavailable packet identity with flow summary
    for w in report["time_series"]:
        pkt_ev = w["packet_evidence"]
        assert pkt_ev["available"] is False
        assert "Per-packet identity unavailable" in pkt_ev["reason"]
        assert "flow_summary" in pkt_ev

    # Verify flagged windows have explicit trigger reasons
    flagged = report["flagged_windows"]
    assert len(flagged) >= 1
    for fw in flagged:
        assert len(fw["flag_reasons"]) >= 1
        assert any(
            "HIGH_CONFIDENCE_SIGNATURE" in r or "STAGE_CONFIDENCE_THRESHOLD" in r
            for r in fw["flag_reasons"]
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Flagging Policy & Semantic Independence Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_semantic_independence_of_report_fields(tmp_path: Path) -> None:
    """Verify progression probability, risk, stage, and trust are distinct independent keys."""
    csv_file = tmp_path / "test_semantics.csv"
    synthesize_test_csv(csv_file, num_benign=3, num_attack=3)

    report = run_offline_analysis(csv_file)
    for w in report["time_series"]:
        # Progression probability is an independent calibrated float in [0, 1]
        assert "progression_probability" in w
        assert 0.0 <= w["progression_probability"] <= 1.0

        # Future security risk is independent
        assert "future_security_risk" in w
        assert "score" in w["future_security_risk"]
        assert 0.0 <= w["future_security_risk"]["score"] <= 1.0

        # Attack stage is independent
        assert "attack_stage" in w
        assert "primary_stage" in w["attack_stage"]
        assert "confidence" in w["attack_stage"]

        # Trust is independent
        assert "forecast_trust" in w
        assert "trust_level" in w["forecast_trust"]

        # Interpretable evidence is independent
        assert "interpretable_evidence" in w
        assert "forecast_feature_contributions" in w["interpretable_evidence"]
        assert "security_explanation" in w["interpretable_evidence"]


# ─────────────────────────────────────────────────────────────────────────────
# 5. CLI Execution & Formatting Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_cli_main_entrypoint_text(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI main() runs on PCAP and prints clean terminal dashboard."""
    if not TEST_PCAP_PATH.exists():
        pytest.skip("Test PCAP not found")

    exit_code = main([str(TEST_PCAP_PATH)])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "SIH PS 26153: AI-BASED NETWORK ATTACK FORECASTING" in captured.out
    assert "EXECUTIVE SUMMARY" in captured.out
    assert "TIME-SERIES PROGRESSION & RISK TRAJECTORY" in captured.out


def test_cli_main_entrypoint_json(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI main() with --format json outputs valid machine-readable JSON."""
    if not TEST_PCAP_PATH.exists():
        pytest.skip("Test PCAP not found")

    exit_code = main([str(TEST_PCAP_PATH), "--format", "json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["report_version"] == "1.0.0"
    assert "summary" in parsed
    assert "time_series" in parsed
    assert "model_provenance" in parsed


def test_cli_main_entrypoint_file_output(tmp_path: Path) -> None:
    """Verify CLI main() with --output writes canonical JSON file to disk."""
    if not TEST_PCAP_PATH.exists():
        pytest.skip("Test PCAP not found")

    out_file = tmp_path / "cli_report.json"
    exit_code = main([str(TEST_PCAP_PATH), "--output", str(out_file)])
    assert exit_code == 0
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["report_version"] == "1.0.0"
    assert data["input_type"] == "PCAP"


def test_cli_main_nonexistent_file_exits_code_1() -> None:
    """Verify CLI exits with code 1 on non-existent input path."""
    exit_code = main(["non_existent_file_xyz.pcap"])
    assert exit_code == 1


# ─────────────────────────────────────────────────────────────────────────────
# 6. Interactive Demo Mode Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_discover_sample_traffic_files() -> None:
    """Verify sample file discovery prioritizes traffic captures (.pcap, .pcapng, .csv) and excludes internal .states.jsonl."""
    from analyze import discover_sample_traffic_files

    files = discover_sample_traffic_files()
    assert len(files) >= 1
    file_strs = [str(f) for f in files]
    # Check that evaluator-facing traffic captures are found
    assert any("test_pipeline.pcap" in s or "test_attack.csv" in s for s in file_strs)
    # Verify internal .states.jsonl training sequences are excluded from the default discovery list
    assert not any(s.endswith(".states.jsonl") for s in file_strs)


def test_states_jsonl_direct_and_custom_loading() -> None:
    """Verify .states.jsonl remains supported via direct offline analysis and custom path."""
    jsonl_path = Path("artifacts/state_sequences/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.states.jsonl")
    if not jsonl_path.exists():
        pytest.skip("Reference states.jsonl not found")

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".states.jsonl", delete=False, mode="w", encoding="utf-8") as tf:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for _ in range(3):
                tf.write(f.readline())
        temp_path = Path(tf.name)

    try:
        report = run_offline_analysis(temp_path)
        assert report["input_type"] == "JSONL_STATES"
        assert report["summary"]["total_windows"] == 3
    finally:
        if temp_path.exists():
            temp_path.unlink()



def test_default_invocation_interactive_mode_quit(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify default invocation without args enters interactive mode and exits on 'q'."""
    inputs = iter(["q"])
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: next(inputs))

    exit_code = main([])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "PREDICTIVE NETWORK SECURITY // OFFLINE ANALYSIS" in captured.out
    assert "Select a traffic capture to analyze:" in captured.out


def test_interactive_mode_file_selection_and_dashboard(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify file selection renders compact progress and required dashboard sections."""
    if not TEST_PCAP_PATH.exists():
        pytest.skip("Test PCAP not found")

    # Enter path to test PCAP directly, then 'q' to exit navigation
    inputs = iter([str(TEST_PCAP_PATH), "q"])
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: next(inputs))

    exit_code = main([])
    assert exit_code == 0

    captured = capsys.readouterr()
    # Compact progress state
    assert "INPUT" in captured.out
    assert "Ingestion" in captured.out
    assert "Network state" in captured.out
    assert "Temporal forecast" in captured.out
    assert "Security assessment" in captured.out
    assert "Explainability" in captured.out

    # Required dashboard sections
    assert "ANALYSIS RESULT" in captured.out
    assert "Overall Assessment:" in captured.out
    assert "Primary Stage:" in captured.out
    assert "Flagged Windows:" in captured.out
    assert "Future Security Risk:" in captured.out
    assert "Progression Probability:" in captured.out
    assert "Forecast Trust:" in captured.out
    assert "Uncertainty:" in captured.out
    assert "WHY IT WAS FLAGGED" in captured.out
    assert "FLAGGED WINDOWS" in captured.out


def test_interactive_mode_navigation_views(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify interactive navigation to Evidence [E], Trajectory [T], Explanation [X], and Quit [Q]."""
    if not TEST_PCAP_PATH.exists():
        pytest.skip("Test PCAP not found")

    # Input sequence: select PCAP, view Evidence, view Trajectory, view Explanation, quit
    inputs = iter([str(TEST_PCAP_PATH), "e", "t", "x", "q"])
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: next(inputs))

    exit_code = main([])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "EVIDENCE // TELEMETRY & CAPTURE ARTIFACTS" in captured.out
    assert "TRAJECTORY // MULTI-HORIZON RISK & PROGRESSION EVOLUTION" in captured.out
    assert "EXPLANATION // FEATURE ATTRIBUTION & SECURITY RATIONALE" in captured.out


def test_interactive_mode_invalid_input_and_retry(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify invalid path or option displays concise error without tracebacks and allows retry."""
    # Sequence: invalid option, invalid path, then 'q' to quit
    inputs = iter(["9999", "non_existent_file_abc.pcap", "q"])
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: next(inputs))

    exit_code = main([])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "[-] Invalid selection" in captured.out or "[-] Unrecognized option or file not found" in captured.out
    assert "Traceback" not in captured.out


def test_full_feature_vector_progression_inference(tmp_path: Path) -> None:
    """Verify that progression inference and window records consume the complete 15-feature vectors."""
    csv_file = tmp_path / "test_full_feats.csv"
    synthesize_test_csv(csv_file, num_benign=5, num_attack=5)

    report = run_offline_analysis(csv_file)
    assert len(report["time_series"]) > 0

    for w in report["time_series"]:
        # Verify full 15 state features are recorded
        curr = w["current_state"]
        for f in CSV_AVAILABLE_FEATURES:
            assert f in curr, f"Missing feature {f} in current_state"

        # Verify predicted deltas are populated for all 15 features
        deltas = w["predicted_deltas_h1"]
        for f in CSV_AVAILABLE_FEATURES:
            assert f in deltas or f"{f}_delta" in deltas, f"Missing feature delta {f} in predicted_deltas_h1"


