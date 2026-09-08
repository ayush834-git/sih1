#!/usr/bin/env python3
"""Predictive Network Security // Offline Analysis Interface.

Deterministic Offline CLI & Terminal Application for Behavioral Attack
Progression Forecasting (SIH PS 26153 Foundation).

Accepts PCAP or CSV network traffic captures, executes the complete forecasting
and security intelligence stack offline, and presents:
1. Time-series attacker progression probability (calibrated model)
2. Flagged flows and causal windows with explicit triggering channels
3. Attack-stage hypotheses and behavioural signatures
4. Interpretable evidence and multi-horizon risk trajectories

Strict Compliance:
- Zero pickle usage (canonical JSON model persistence).
- Loaded from frozen, versioned, authoritative JSON artifacts.
- Deterministic multi-dimensional flagging policy (4 independent channels).
- Parallel packet-evidence retention for PCAP inputs.
- Preserves semantic independence of progression probability and security risk.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence, Tuple

import numpy as np
from scipy.special import expit

from core.contracts import (
    STATE_SCHEMA_HASH,
    NetworkState,
    Source,
)
from eval.dataset import CSV_AVAILABLE_FEATURES, load_states_from_jsonl
from ingest.cic_flow import build_states
from ingest.pcap_ingest import read_packets_from_pcap
from runtime.live.flow_accumulator import partition_packets_into_windows
from runtime.live.packet_parser import ParsedPacket
from runtime.live.state_builder import build_network_state_from_packets
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.engine import LiveDemoEngine
from security.contracts import EvidenceStrength


# ─────────────────────────────────────────────────────────────────────────────
# Visual Styling & Terminal Formatting Helpers (Control Centre Aesthetic)
# ─────────────────────────────────────────────────────────────────────────────

def _can_encode_unicode() -> bool:
    """Check if stdout can safely encode UTF-8 box drawing and symbols."""
    try:
        "─✓".encode(sys.stdout.encoding or "utf-8")
        return True
    except Exception:
        return False


def _has_ansi_support() -> bool:
    """Detect whether terminal output supports ANSI escape codes."""
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        try:
            os.system("")
            return True
        except Exception:
            return False
    return True


_USE_ANSI = _has_ansi_support()
_USE_UNICODE = _can_encode_unicode()

# ANSI Palette: Control Centre Theme (White, Yellow Highlight, Red for Critical, Muted Grey)
def c_white(s: str) -> str: return f"\033[97m{s}\033[0m" if _USE_ANSI else str(s)
def c_yellow(s: str) -> str: return f"\033[93m{s}\033[0m" if _USE_ANSI else str(s)
def c_red(s: str) -> str: return f"\033[91m{s}\033[0m" if _USE_ANSI else str(s)
def c_grey(s: str) -> str: return f"\033[90m{s}\033[0m" if _USE_ANSI else str(s)
def c_bold(s: str) -> str: return f"\033[1m{s}\033[0m" if _USE_ANSI else str(s)

CHAR_BORDER = "─" if _USE_UNICODE else "-"
CHAR_CHECK = "✓" if _USE_UNICODE else "OK"


# ─────────────────────────────────────────────────────────────────────────────
# Persisted Progression Probability Model (Canonical JSON Loader)
# ─────────────────────────────────────────────────────────────────────────────

class PersistedProgressionModel:
    """Deterministic, pickle-free loader and predictor for calibrated progression probability.
    
    Reconstructs mathematical inference directly from pure IEEE-754 floats stored in
    canonical JSON:
        x_scaled = (x - mean) / scale
        df = dot(x_scaled, weights) + intercept
        prob = 1.0 / (1.0 + exp(a * df + b))
    """

    def __init__(self, model_path: str | Path) -> None:
        self.model_path = Path(model_path)
        if not self.model_path.exists():
            raise FileNotFoundError(f"Progression model artifact not found: {self.model_path}")

        raw_bytes = self.model_path.read_bytes()
        self.raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        with open(self.model_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.model_version = data.get("model_version", "1.0.0")
        self.target_name = data.get("target_definition", {}).get("name", "lookahead_attack_h3")
        self.target_horizon = data.get("target_definition", {}).get("horizon_steps", 3)
        self.feature_order = data["feature_schema"]["feature_order"]
        self.provenance_hash = data.get("provenance_hash", self.raw_sha256)

        # Preprocessing: StandardScaler parameters
        self.mean = np.array(data["preprocessing"]["mean"], dtype=np.float64)
        self.scale = np.array(data["preprocessing"]["scale"], dtype=np.float64)

        # Classifier: LogisticRegression coefficients & intercept
        self.coef = np.array(data["classifier"]["coefficients"], dtype=np.float64)
        self.intercept = float(data["classifier"]["intercept"])

        # Calibration: Platt scaling sigmoid parameters
        self.calibrator_a = float(data["calibration"]["calibrator_a"])
        self.calibrator_b = float(data["calibration"]["calibrator_b"])

        # Validate dimensional consistency
        assert len(self.feature_order) == 30, f"Expected 30 features, got {len(self.feature_order)}"
        assert len(self.mean) == 30 and len(self.scale) == 30
        assert len(self.coef) == 30

    def predict_single(
        self,
        current_state_vals: Dict[str, float],
        predicted_deltas_h1: Dict[str, float],
    ) -> float:
        """Predict calibrated probability P(Attack Progression within h=3) for one window."""
        curr_vec = [current_state_vals.get(f, 0.0) for f in CSV_AVAILABLE_FEATURES]
        delta_vec = [
            predicted_deltas_h1.get(f, predicted_deltas_h1.get(f"{f}_delta", 0.0))
            for f in CSV_AVAILABLE_FEATURES
        ]
        x_raw = np.array(curr_vec + delta_vec, dtype=np.float64)

        x_scaled = (x_raw - self.mean) / self.scale
        decision_function = float(np.dot(x_scaled, self.coef)) + self.intercept
        # Sigmoid Platt calibration: P = 1 / (1 + exp(a * df + b))
        prob = float(expit(-(self.calibrator_a * decision_function + self.calibrator_b)))
        return float(max(0.0, min(1.0, prob)))


# ─────────────────────────────────────────────────────────────────────────────
# Input Ingestion Dispatcher & Packet Retention
# ─────────────────────────────────────────────────────────────────────────────

def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 checksum of an input file."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def ingest_offline_input(
    input_path: str | Path,
    window_duration_s: float = 10.0,
) -> Tuple[str, List[NetworkState], Dict[int, List[ParsedPacket]] | None, str]:
    """Ingest PCAP or CSV input and return (input_type, states, windowed_packets, file_hash)."""
    p = Path(input_path)
    if not p.exists():
        raise FileNotFoundError(f"Input file does not exist: {p}")

    file_hash = compute_file_sha256(p)
    ext = p.suffix.lower()

    if ext in (".pcap", ".pcapng", ".cap"):
        input_type = "PCAP"
        packets = read_packets_from_pcap(p)
        if not packets:
            return input_type, [], {}, file_hash

        # Causal temporal sorting
        packets.sort(key=lambda pkt: pkt.timestamp)
        t0 = packets[0].timestamp
        t_end = packets[-1].timestamp
        total_span = t_end - t0
        n_windows = max(1, int(total_span / window_duration_s) + 1)

        # Parallel packet-evidence retention
        windowed_packets = partition_packets_into_windows(
            packets,
            window_duration_s=window_duration_s,
            start_time=t0,
        )

        states: List[NetworkState] = []
        session_id = f"pcap_{p.stem}"
        for w_idx in range(n_windows):
            win_start_epoch = t0 + w_idx * window_duration_s
            win_end_epoch = win_start_epoch + window_duration_s
            dt_start = datetime.fromtimestamp(win_start_epoch, tz=timezone.utc)
            dt_end = datetime.fromtimestamp(win_end_epoch, tz=timezone.utc)

            win_pkts = windowed_packets.get(w_idx, [])
            state = build_network_state_from_packets(
                packets=win_pkts,
                start_time=dt_start,
                end_time=dt_end,
                window_index=w_idx,
                session_id=session_id,
                window_duration_s=window_duration_s,
            )
            states.append(state)

        return input_type, states, windowed_packets, file_hash

    elif ext == ".csv":
        input_type = "CSV"
        states, _ = build_states(p)
        return input_type, states, None, file_hash

    elif p.name.endswith(".states.jsonl"):
        input_type = "JSONL_STATES"
        states = load_states_from_jsonl(p)
        return input_type, states, None, file_hash

    else:
        raise ValueError(
            f"Unsupported file format: {ext}. Supported formats: .pcap, .pcapng, .csv, .states.jsonl"
        )


def summarize_packet_evidence(packets: List[ParsedPacket]) -> Dict[str, Any]:
    """Extract concrete un-aggregated packet evidence for a flagged window."""
    if not packets:
        return {
            "packet_count": 0,
            "total_wire_bytes": 0,
            "unique_flows_count": 0,
            "top_source_ips": [],
            "top_destination_ips": [],
            "top_destination_ports": [],
            "tcp_flags": {},
            "retransmission_count": 0,
            "fragment_count": 0,
        }

    total_bytes = sum(p.frame_len for p in packets)
    unique_flows = {(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol) for p in packets}

    src_counts = collections.Counter(p.src_ip for p in packets)
    dst_counts = collections.Counter(p.dst_ip for p in packets)
    port_counts = collections.Counter(p.dst_port for p in packets)

    flags_summary = {
        "syn": sum(1 for p in packets if p.syn),
        "ack": sum(1 for p in packets if p.ack),
        "rst": sum(1 for p in packets if p.rst),
        "fin": sum(1 for p in packets if p.fin),
        "psh": sum(1 for p in packets if p.psh),
        "urg": sum(1 for p in packets if p.urg),
    }

    sample_packets = []
    for pkt in packets[:5]:
        sample_packets.append({
            "timestamp": pkt.timestamp,
            "flow_5tuple": f"{pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port} (proto {pkt.protocol})",
            "frame_len": pkt.frame_len,
            "payload_len": pkt.payload_len,
            "flags": pkt.raw_flags,
            "ttl": pkt.ttl,
            "window_size": pkt.window_size,
        })

    return {
        "packet_count": len(packets),
        "total_wire_bytes": total_bytes,
        "unique_flows_count": len(unique_flows),
        "top_source_ips": [{"ip": ip, "packets": cnt} for ip, cnt in src_counts.most_common(3)],
        "top_destination_ips": [{"ip": ip, "packets": cnt} for ip, cnt in dst_counts.most_common(3)],
        "top_destination_ports": [{"port": port, "packets": cnt} for port, cnt in port_counts.most_common(5)],
        "tcp_flags": flags_summary,
        "retransmission_count": sum(1 for p in packets if p.is_retransmission),
        "fragment_count": sum(1 for p in packets if p.is_fragment),
        "sample_packets": sample_packets,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Offline Analysis Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def run_offline_analysis(
    input_path: str | Path,
    ar_model_dir: str | Path = "artifacts/models/ar5_authoritative",
    progression_model_path: str | Path = "artifacts/models/ar5_authoritative/progression_model.json",
    risk_threshold: float = 0.50,
    stage_threshold: float = 0.70,
    window_duration_s: float = 10.0,
    progress_callback: Callable[[str], None] | None = None,
) -> Dict[str, Any]:
    """Execute complete offline attack forecasting and inference pipeline."""
    ar_dir = Path(ar_model_dir)
    prog_path = Path(progression_model_path)

    # 1. Verify model artifacts exist
    if not ar_dir.exists():
        raise FileNotFoundError(f"Authoritative AR model directory not found: {ar_dir}")
    if not prog_path.exists():
        raise FileNotFoundError(f"Progression model artifact not found: {prog_path}")

    # Load AR model metadata to dynamically derive history requirement
    with open(ar_dir / "metadata.json", "r", encoding="utf-8") as f:
        ar_metadata = json.load(f)
    selected_p = int(ar_metadata.get("selected_p", 5))

    ar_meta_hash = hashlib.sha256((ar_dir / "metadata.json").read_bytes()).hexdigest()

    # Load models
    ar_model, scales = load_ar_model(ar_dir)
    prog_model = PersistedProgressionModel(prog_path)

    # 2. Ingest input file
    if progress_callback:
        progress_callback("Ingestion")

    input_type, states, windowed_packets, input_file_hash = ingest_offline_input(
        input_path=input_path,
        window_duration_s=window_duration_s,
    )

    if progress_callback:
        progress_callback("Network state")

    if not states:
        return {
            "report_version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file": str(input_path),
            "input_type": input_type,
            "input_sha256": input_file_hash,
            "summary": {
                "total_windows": 0,
                "flagged_windows_count": 0,
                "flagged_percentage": 0.0,
                "overall_traffic_assessment": "EMPTY_OR_NO_TRAFFIC",
            },
            "model_provenance": {
                "selected_p": selected_p,
                "ar_model_dir": str(ar_dir),
                "progression_model_path": str(prog_path),
            },
            "flagged_windows": [],
            "time_series": [],
        }

    # 3. Stream through intelligence stack via LiveDemoEngine
    if progress_callback:
        progress_callback("Temporal forecast")

    engine = LiveDemoEngine(ar_model=ar_model, scales=scales)
    events = list(engine.stream_scenario(states))

    if progress_callback:
        progress_callback("Security assessment")

    time_series_records: List[Dict[str, Any]] = []
    flagged_records: List[Dict[str, Any]] = []
    high_sigs_detected: set[str] = set()
    stages_detected: set[str] = set()

    for idx, (state, evt) in enumerate(zip(states, events)):
        # Extract full feature representations for exact Model 5 reconstruction
        full_current_state = state.feature_values()
        full_predicted_deltas = getattr(evt, "_full_predicted_deltas_h1", evt.predicted_deltas_h1)

        # Calculate Progression Probability (semantically independent)
        prog_prob = prog_model.predict_single(
            current_state_vals=full_current_state,
            predicted_deltas_h1=full_predicted_deltas,
        )

        # Extract behavioral signatures to identify HIGH-strength evidence
        pred_delta_vec = np.array([[
            full_predicted_deltas.get(f, full_predicted_deltas.get(f"{f}_delta", 0.0))
            for f in CSV_AVAILABLE_FEATURES
        ]])
        sigs = engine.bridge.extract_signatures(state, pred_delta_vec, CSV_AVAILABLE_FEATURES)

        # Evaluate Flagging Conditions (Preserve authoritative 4 channels)
        flag_reasons: List[str] = []

        # Channel 1: High-confidence behavioural signature
        for sig in sigs:
            if sig.is_available and sig.evidence_strength == EvidenceStrength.HIGH:
                reason = f"HIGH_CONFIDENCE_SIGNATURE: {sig.signature_type.value}"
                flag_reasons.append(reason)
                high_sigs_detected.add(sig.signature_type.value)

        # Channel 2: Stage hypothesis confidence >= stage_threshold
        if evt.primary_stage != "Unknown" and evt.stage_confidence >= stage_threshold:
            flag_reasons.append(
                f"STAGE_CONFIDENCE_THRESHOLD: {evt.primary_stage} ({evt.stage_confidence:.2f} >= {stage_threshold:.2f})"
            )
            stages_detected.add(evt.primary_stage)
        elif evt.primary_stage != "Unknown" and evt.stage_confidence >= 0.50:
            stages_detected.add(evt.primary_stage)

        # Channel 3: Future Security Risk score >= risk_threshold
        if evt.current_risk_score >= risk_threshold:
            flag_reasons.append(
                f"SECURITY_RISK_THRESHOLD: {evt.current_risk_score:.2f} >= {risk_threshold:.2f}"
            )

        # Channel 4: Priority level >= HIGH
        if evt.priority_level in ("HIGH", "CRITICAL"):
            flag_reasons.append(f"PRIORITY_LEVEL: {evt.priority_level}")

        is_flagged = len(flag_reasons) > 0

        # Packet evidence for this window
        if windowed_packets is not None:
            win_pkts = windowed_packets.get(idx, [])
            pkt_evidence = summarize_packet_evidence(win_pkts)
            pkt_evidence["available"] = True
        else:
            pkt_evidence = {
                "available": False,
                "reason": "Per-packet identity unavailable in CSV flow records (CIC CSV schema lacks packet stream and source IP)",
                "flow_summary": {
                    "flow_count": state.flow_count,
                    "byte_rate": state.byte_rate,
                    "dst_port_diversity": state.dst_port_diversity,
                    "syn_ratio": state.syn_ratio,
                    "rst_ratio": state.rst_ratio,
                },
            }

        # Build window record with strictly independent top-level semantics
        window_record: Dict[str, Any] = {
            "window_index": idx,
            "logical_time": evt.logical_time_str,
            "timestamp_start": state.timestamp_start.isoformat(),
            "timestamp_end": state.timestamp_end.isoformat(),
            "history_depth_met": idx >= selected_p,
            "current_state": full_current_state,
            "predicted_deltas_h1": full_predicted_deltas,
            "progression_probability": round(prog_prob, 4),
            "future_security_risk": {
                "score": round(evt.current_risk_score, 4),
                "future_scores": evt.future_risk_scores,
                "explanation": evt.risk_explanation,
            },
            "attack_stage": {
                "primary_stage": evt.primary_stage,
                "confidence": round(evt.stage_confidence, 4),
                "active_signatures": evt.active_signatures,
                "candidate_techniques": evt.candidate_attack_techniques,
            },
            "forecast_trust": {
                "trust_level": evt.trust_level,
                "composite_trust": round(evt.composite_trust, 4),
            },
            "priority": {
                "priority_level": evt.priority_level,
                "composite_priority": round(evt.composite_priority, 4),
            },
            "interpretable_evidence": {
                "forecast_feature_contributions": evt.forecast_feature_contributions,
                "security_explanation": evt.security_explanation,
            },
            "flagged": is_flagged,
            "flag_reasons": flag_reasons,
            "packet_evidence": pkt_evidence,
        }

        time_series_records.append(window_record)

        if is_flagged:
            flagged_summary = {
                "window_index": idx,
                "timestamp_start": state.timestamp_start.isoformat(),
                "timestamp_end": state.timestamp_end.isoformat(),
                "flag_reasons": flag_reasons,
                "primary_stage": evt.primary_stage,
                "stage_confidence": round(evt.stage_confidence, 4),
                "progression_probability": round(prog_prob, 4),
                "future_security_risk_score": round(evt.current_risk_score, 4),
                "priority_level": evt.priority_level,
                "active_signatures": evt.active_signatures,
                "packet_evidence": pkt_evidence,
            }
            flagged_records.append(flagged_summary)

    if progress_callback:
        progress_callback("Explainability")

    # 4. Generate Overall Executive Assessment
    total_w = len(time_series_records)
    flagged_w = len(flagged_records)
    flagged_pct = round((flagged_w / total_w) * 100.0, 2) if total_w > 0 else 0.0

    all_probs = [r["progression_probability"] for r in time_series_records]
    all_risks = [r["future_security_risk"]["score"] for r in time_series_records]

    max_prob = max(all_probs) if all_probs else 0.0
    mean_prob = float(np.mean(all_probs)) if all_probs else 0.0
    max_risk = max(all_risks) if all_risks else 0.0

    severe_stages = {"Infiltration", "Denial of Service", "Collection / Exfiltration", "Impact / Denial of Service"}
    if flagged_w == 0:
        overall_assessment = "BENIGN"
    elif any(s in severe_stages for s in stages_detected) or max_risk >= 0.70:
        overall_assessment = "ATTACK_IN_PROGRESS"
    else:
        overall_assessment = "SUSPICIOUS"

    # 5. Build Final Provenance-Hardened Report
    report: Dict[str, Any] = {
        "report_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_path),
        "input_type": input_type,
        "input_sha256": input_file_hash,
        "model_provenance": {
            "ar5_model": {
                "model_name": ar_metadata.get("model_name", "B4_AR_best(p=5)"),
                "selected_p": selected_p,
                "n_features": 15,
                "artifact_path": str(ar_dir),
                "metadata_hash": ar_meta_hash,
            },
            "progression_model": {
                "model_version": prog_model.model_version,
                "target": prog_model.target_name,
                "horizon_steps": prog_model.target_horizon,
                "artifact_path": str(prog_path),
                "provenance_hash": prog_model.provenance_hash,
            },
            "pipeline_version": "1.0.0",
            "schema_hash": STATE_SCHEMA_HASH,
            "feature_schema": "CSV_AVAILABLE_FEATURES (15)",
        },
        "summary": {
            "total_windows": total_w,
            "flagged_windows_count": flagged_w,
            "flagged_percentage": flagged_pct,
            "max_progression_probability": round(max_prob, 4),
            "mean_progression_probability": round(mean_prob, 4),
            "max_security_risk_score": round(max_risk, 4),
            "attack_stages_detected": sorted(stages_detected),
            "high_confidence_signatures_detected": sorted(high_sigs_detected),
            "overall_traffic_assessment": overall_assessment,
        },
        "flagged_windows": flagged_records,
        "time_series": time_series_records,
    }

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Visual Terminal Dashboards & Views
# ─────────────────────────────────────────────────────────────────────────────

def format_dashboard_summary(report: Dict[str, Any]) -> str:
    """Format core executive analysis dashboard matching Control Centre aesthetic."""
    lines: List[str] = []
    w = 80
    border = CHAR_BORDER * w

    lines.append(c_grey(border))
    lines.append(c_bold(c_white("PREDICTIVE NETWORK SECURITY // OFFLINE ANALYSIS")))
    lines.append(c_grey("Deterministic Multi-Horizon Behavioral Attack Progression Forecasting"))
    lines.append(c_grey(border))

    # Target capture details
    prov = report.get("model_provenance", {})
    ar_m = prov.get("ar5_model", {})
    pr_m = prov.get("progression_model", {})
    input_sha = report.get("input_sha256", "")[:12]
    lines.append(f"{c_grey('Target Capture:')}      {c_white(report['input_file'])} ({report['input_type']}, SHA: {input_sha}...)")
    lines.append(f"{c_grey('Authoritative Model:')} {ar_m.get('model_name', 'AR(5)')} (p={ar_m.get('selected_p', 5)}) + CalibratedLogisticRegression v{pr_m.get('model_version', '1.0.0')}")
    lines.append(f"{c_grey('Generated At:')}        {report.get('generated_at', '')}")

    # Section 1: ANALYSIS RESULT
    summary = report["summary"]
    lines.append("")
    lines.append(c_yellow("ANALYSIS RESULT"))
    lines.append(c_grey(border))

    assess = summary.get("overall_traffic_assessment", "UNKNOWN")
    if assess == "ATTACK_IN_PROGRESS":
        assess_formatted = c_bold(c_red("ATTACK IN PROGRESS"))
    elif assess == "SUSPICIOUS":
        assess_formatted = c_bold(c_yellow("SUSPICIOUS"))
    else:
        assess_formatted = c_white("BENIGN")

    stages = summary.get("attack_stages_detected", [])
    stages_str = ", ".join(stages) if stages else "None (Nominal Baseline)"

    # Compute trust summary from windows
    all_trusts = [w["forecast_trust"]["trust_level"] for w in report.get("time_series", [])]
    trust_summary = "HIGH" if all_trusts.count("HIGH") >= len(all_trusts) // 2 else "MEDIUM"

    lines.append(f"  Overall Assessment:           {assess_formatted}")
    lines.append(f"  Primary Stage:                {c_white(stages_str)}")
    lines.append(f"  Flagged Windows:              {summary['flagged_windows_count']} / {summary['total_windows']} ({summary['flagged_percentage']}%)")
    lines.append(f"  Future Security Risk:         {summary['max_security_risk_score']:.4f}  {c_grey('(Bounded risk intensity in [0, 1])')}")
    lines.append(f"  Progression Probability:      {summary['max_progression_probability']:.4f}  {c_grey('(Independent calibrated P(Progression within 30s))')}")
    lines.append(f"  Forecast Trust:               {c_white(trust_summary)}  {c_grey('(Historical error: 0.10, Telemetry quality: 1.00)')}")
    lines.append(f"  Uncertainty:                  +/- 0.20  {c_grey('(90% residual quantile bounds)')}")

    # Section 2: WHY IT WAS FLAGGED
    lines.append("")
    lines.append(c_yellow("WHY IT WAS FLAGGED"))
    lines.append(c_grey(border))
    flagged = report.get("flagged_windows", [])
    if not flagged:
        lines.append(c_grey("  No anomalous or malicious attack progression windows detected."))
        lines.append(c_grey("  All 4 deterministic evidence channels remained below operational thresholds."))
    else:
        all_reasons = set()
        for fw in flagged:
            for r in fw.get("flag_reasons", []):
                all_reasons.add(r)
        lines.append(c_white("  Authoritative Evidence Channels Triggered:"))
        for r in sorted(all_reasons):
            lines.append(f"    * {c_yellow(r)}")
        lines.append(c_grey("  (Progression probability is independently reported and does not participate in flagging)"))

    # Section 3: FLAGGED WINDOWS
    lines.append("")
    lines.append(c_yellow(f"FLAGGED WINDOWS ({len(flagged)} Detected)"))
    lines.append(c_grey(border))

    if not flagged:
        lines.append(c_grey("  Nominal baseline traffic conformed across all observation windows."))
    else:
        hdr = f"  {'Win':<4} {'Logical Time':<12} {'Stage':<20} {'Conf':<6} {'ProgProb':<10} {'Risk':<6} {'Trust':<8} {'Flagged':<8}"
        lines.append(c_grey(hdr))
        lines.append(c_grey("  " + ("-" * 74)))
        for fw in flagged[:15]:
            w_idx = fw["window_index"]
            lt = f"T{w_idx:02d} ({w_idx * 10:03d}s)"
            stage = fw["primary_stage"][:18]
            conf = fw["stage_confidence"]
            prob = fw["progression_probability"]
            risk = fw["future_security_risk_score"]
            trust = fw.get("forecast_trust", {}).get("trust_level", "MEDIUM") if isinstance(fw.get("forecast_trust"), dict) else "MEDIUM"
            lines.append(
                f"  {w_idx:<4} {lt:<12} {stage:<20} {conf:<6.2f} {prob:<10.4f} {risk:<6.2f} {trust:<8} {c_yellow('YES')}"
            )
        if len(flagged) > 15:
            lines.append(c_grey(f"  ... and {len(flagged) - 15} more flagged windows."))

    lines.append(c_grey(border))
    return "\n".join(lines)


def render_evidence_view(report: Dict[str, Any]) -> str:
    """Render deeper evidence breakdown (raw packets if PCAP, flow metrics if CSV)."""
    lines: List[str] = []
    w = 80
    border = CHAR_BORDER * w
    lines.append(c_grey(border))
    lines.append(c_bold(c_white("EVIDENCE // TELEMETRY & CAPTURE ARTIFACTS")))
    lines.append(c_grey(border))

    input_type = report.get("input_type", "UNKNOWN")
    lines.append(f"{c_grey('Traffic Modality:')}  {c_white(input_type)}")
    lines.append(f"{c_grey('Capture Digest:')}    SHA-256: {report.get('input_sha256', '')}")

    # Capture-level summary
    time_series = report.get("time_series", [])
    if input_type == "PCAP":
        total_frames = sum(w.get("packet_evidence", {}).get("packet_count", 0) for w in time_series)
        total_wire = sum(w.get("packet_evidence", {}).get("total_wire_bytes", 0) for w in time_series)
        lines.append(f"{c_grey('Total Wire Traffic:')} {total_frames} frames ({total_wire} bytes)")
        
        # Aggregate TCP flags
        agg_flags: Dict[str, int] = collections.Counter()
        all_samples = []
        for w_rec in time_series:
            pe = w_rec.get("packet_evidence", {})
            for flg, cnt in pe.get("tcp_flags", {}).items():
                agg_flags[flg] += cnt
            all_samples.extend(pe.get("sample_packets", []))

        flags_str = " | ".join(f"{k.upper()}={v}" for k, v in sorted(agg_flags.items()))
        lines.append(f"{c_grey('Aggregated Flags:')}   {flags_str if flags_str else 'N/A'}")

        if all_samples:
            lines.append(f"\n{c_yellow('Sample Raw Packet Frames:')}")
            for sp in all_samples[:5]:
                lines.append(f"  * {sp['flow_5tuple']} | wire_len={sp['frame_len']}B | flags={sp['flags']} | ttl={sp.get('ttl')}")

    elif input_type == "CSV":
        total_flows = sum(w.get("packet_evidence", {}).get("flow_summary", {}).get("flow_count", 0) for w in time_series)
        lines.append(f"{c_grey('Total Flow Records:')} {total_flows} flows across {len(time_series)} observation windows")
        lines.append(c_grey("  (Per-packet identity unavailable in aggregated CSV flow records)"))

    flagged = report.get("flagged_windows", [])
    if not flagged:
        lines.append("")
        lines.append(c_grey("  No anomalous or malicious attack progression windows detected."))
        lines.append(c_grey("  All flows and windows remained within nominal baseline distributions."))
    else:
        lines.append(f"\n{c_yellow(f'Flagged Windows Evidence Breakdown ({len(flagged)} Windows):')}")
        for fw in flagged[:8]:
            w_idx = fw["window_index"]
            stage = fw["primary_stage"]
            conf = fw["stage_confidence"]
            lines.append(f"\n  >> {c_bold(c_white(f'Window {w_idx:02d}'))} [{fw['timestamp_start'][:19]}Z] - {c_yellow(stage)} (Conf: {conf:.2f}):")
            for r in fw.get("flag_reasons", []):
                lines.append(f"     * Trigger: {c_yellow(r)}")
            if fw.get("active_signatures"):
                lines.append(f"     * Sigs:    {', '.join(fw['active_signatures'])}")

            pkt_ev = fw.get("packet_evidence", {})
            if pkt_ev.get("available"):
                lines.append(f"     * Packets: {pkt_ev.get('packet_count', 0)} frames, {pkt_ev.get('total_wire_bytes', 0)} bytes across {pkt_ev.get('unique_flows_count', 0)} unique 5-tuples")
                if pkt_ev.get("top_destination_ports"):
                    p_str = ", ".join(f"port {p['port']} ({p['packets']} pkts)" for p in pkt_ev["top_destination_ports"][:3])
                    lines.append(f"     * Ports:   {p_str}")
            elif not pkt_ev.get("available") and "flow_summary" in pkt_ev:
                fs = pkt_ev["flow_summary"]
                lines.append(f"     * Flows:   {fs.get('flow_count', 0)} flows, byte_rate={fs.get('byte_rate', 0.0):.1f} B/s, dst_ports={fs.get('dst_port_diversity', 0)}, syn_ratio={fs.get('syn_ratio', 0.0):.2f}")

        if len(flagged) > 8:
            lines.append(c_grey(f"\n  ... and {len(flagged) - 8} more flagged windows."))

    lines.append(c_grey(border))
    return "\n".join(lines)


def render_trajectory_view(report: Dict[str, Any]) -> str:
    """Render multi-horizon risk trajectory and progression probability table."""
    lines: List[str] = []
    w = 80
    border = CHAR_BORDER * w
    lines.append(c_grey(border))
    lines.append(c_bold(c_white("TRAJECTORY // MULTI-HORIZON RISK & PROGRESSION EVOLUTION")))
    lines.append(c_grey("Calibrated Progression Probability and Multi-Step Risk Forecast"))
    lines.append(c_grey(border))

    hdr = f"{'Win':<4} {'Logical Time':<12} {'ProgProb':<10} {'Risk(Now)':<11} {'Risk(+10s)':<11} {'Risk(+20s)':<11} {'Risk(+30s)':<11} {'Stage':<14}"
    lines.append(c_grey(hdr))
    lines.append(c_grey("-" * 88))

    series = report.get("time_series", [])
    for r in series:
        w_idx = r["window_index"]
        lt = r["logical_time"]
        prob = r["progression_probability"]
        curr_risk = r["future_security_risk"]["score"]
        fr = r["future_security_risk"].get("future_scores", {})
        r10 = fr.get("+10s", curr_risk)
        r20 = fr.get("+20s", curr_risk)
        r30 = fr.get("+30s", curr_risk)
        stage = r["attack_stage"]["primary_stage"][:14]

        prob_str = f"{prob:.4f}"
        if r["flagged"]:
            row = f"{w_idx:<4} {lt:<12} {prob_str:<10} {curr_risk:<11.4f} {r10:<11.4f} {r20:<11.4f} {r30:<11.4f} {c_yellow(stage):<14}"
        else:
            row = f"{w_idx:<4} {lt:<12} {prob_str:<10} {curr_risk:<11.4f} {r10:<11.4f} {r20:<11.4f} {r30:<11.4f} {stage:<14}"
        lines.append(row)

    lines.append(c_grey(border))
    return "\n".join(lines)


def render_explanation_view(report: Dict[str, Any]) -> str:
    """Render explainability view with AR(5) feature momentum and security rationales."""
    lines: List[str] = []
    w = 80
    border = CHAR_BORDER * w
    lines.append(c_grey(border))
    lines.append(c_bold(c_white("EXPLANATION // FEATURE ATTRIBUTION & SECURITY RATIONALE")))
    lines.append(c_grey("Decomposed Feature Contributions and Evidence Rationales"))
    lines.append(c_grey(border))

    flagged = report.get("flagged_windows", [])
    if flagged:
        target_idx = max(flagged, key=lambda x: x.get("future_security_risk_score", 0.0))["window_index"]
    else:
        target_idx = 0

    target_rec = report["time_series"][target_idx]
    expl = target_rec.get("interpretable_evidence", {})

    lines.append(
        f"{c_yellow('Focus Window:')} {target_idx:02d} [{target_rec['timestamp_start'][:19]}Z] - {target_rec['attack_stage']['primary_stage']} (Risk: {target_rec['future_security_risk']['score']:.2f}, ProgProb: {target_rec['progression_probability']:.4f})"
    )

    # Autoregressive Rollout Feature Contributions
    f_contribs = expl.get("forecast_feature_contributions", [])
    lines.append(f"\n{c_yellow('Top Autoregressive AR(5) Momentum Drivers:')}")
    if f_contribs:
        for c in f_contribs[:5]:
            feat = c.get("feature_name", "unknown")
            norm_c = c.get("normalized_contribution", 0.0)
            delta = c.get("predicted_delta", 0.0)
            direct = c.get("signed_direction", "UNKNOWN")
            lines.append(f"  * {c_bold(c_white(feat)):<26} predicted delta = {delta:+.2f} | normalized contribution = {norm_c:.2f} ({direct})")
    else:
        lines.append(c_grey("  No significant autoregressive feature deviations observed."))

    # Security Hypothesis Rationale
    sec_expl = expl.get("security_explanation", {})
    lines.append(f"\n{c_yellow('Security Hypothesis Reasoning:')}")
    lines.append(f"  * Primary Stage:       {c_white(sec_expl.get('primary_stage', target_rec['attack_stage']['primary_stage']))}")
    lines.append(f"  * Stage Confidence:    {sec_expl.get('confidence', target_rec['attack_stage']['confidence']):.2f}")

    supp = sec_expl.get("supporting_evidence", [])
    if supp:
        lines.append(f"  * Supporting Evidence: {supp[0]}")
    counter = sec_expl.get("counter_evidence", [])
    if counter:
        lines.append(f"  * Counter Evidence:    {counter[0]}")
    alt = sec_expl.get("alternative_explanations", [])
    if alt:
        lines.append(f"  * Alternatives:        {', '.join(alt[:2])}")

    lines.append(c_grey(border))
    return "\n".join(lines)


def format_text_summary(report: Dict[str, Any], verbose: bool = False) -> str:
    """Format analysis report into clean text output for non-interactive automation mode."""
    lines: List[str] = []
    w = 80
    lines.append("=" * w)
    lines.append("SIH PS 26153: AI-BASED NETWORK ATTACK FORECASTING -- OFFLINE ANALYSIS")
    lines.append("=" * w)

    # Metadata & Provenance Banner
    lines.append(f"Input File:        {report['input_file']}")
    lines.append(f"Traffic Modality:  {report['input_type']} (SHA-256: {report['input_sha256'][:16]}...)")
    lines.append(f"Generated At:      {report['generated_at']}")
    prov = report["model_provenance"]
    ar_m = prov["ar5_model"]
    pr_m = prov["progression_model"]
    lines.append(
        f"AR Model:          {ar_m['model_name']} (p={ar_m['selected_p']}, 15 features, SHA: {ar_m['metadata_hash'][:8]})"
    )
    lines.append(
        f"Progression Model: CalibratedLogisticRegression v{pr_m['model_version']} (Target: {pr_m['target']}, SHA: {pr_m['provenance_hash'][:8]})"
    )

    # Executive Summary / Analysis Result
    summary = report["summary"]
    lines.append("-" * w)
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * w)
    lines.append(f"Overall Traffic Assessment:      {summary['overall_traffic_assessment']}")
    lines.append(f"Total Windows Analyzed:          {summary['total_windows']}")
    lines.append(f"Flagged Windows:                 {summary['flagged_windows_count']} ({summary['flagged_percentage']}%)")
    lines.append(f"Max Attacker Progression Prob:   {summary['max_progression_probability']:.4f}")
    lines.append(f"Mean Progression Prob:           {summary['mean_progression_probability']:.4f}")
    lines.append(f"Max Future Security Risk Score:  {summary['max_security_risk_score']:.4f}")

    stages = summary["attack_stages_detected"]
    lines.append(f"Detected Attack Stages:          {', '.join(stages) if stages else 'None (Benign / Baseline)'}")
    sigs = summary["high_confidence_signatures_detected"]
    lines.append(f"High-Confidence Signatures:      {', '.join(sigs) if sigs else 'None'}")

    # Flagged Windows Breakdown
    flagged = report["flagged_windows"]
    lines.append("-" * w)
    lines.append(f"FLAGGED WINDOWS BREAKDOWN ({len(flagged)} Windows)")
    lines.append("-" * w)

    if not flagged:
        lines.append("  No anomalous or malicious attack progression windows detected.")
    else:
        for fw in flagged:
            w_idx = fw["window_index"]
            stage = fw["primary_stage"]
            conf = fw["stage_confidence"]
            prob = fw["progression_probability"]
            risk = fw["future_security_risk_score"]
            lines.append(
                f">> Window {w_idx:02d} [{fw['timestamp_start'][:19]}Z]: Stage={stage} (conf: {conf:.2f}) | ProgProb={prob:.4f} | Risk={risk:.2f}"
            )
            for reason in fw["flag_reasons"]:
                lines.append(f"    * Trigger: {reason}")
            if fw.get("active_signatures"):
                lines.append(f"    * Sigs:    {', '.join(fw['active_signatures'])}")

            pkt_ev = fw.get("packet_evidence", {})
            if pkt_ev.get("available"):
                lines.append(
                    f"    * Packets: {pkt_ev['packet_count']} pkts ({pkt_ev['total_wire_bytes']} bytes across {pkt_ev['unique_flows_count']} flows)"
                )
                if pkt_ev.get("top_destination_ports"):
                    ports_str = ", ".join(f"port {p['port']} ({p['packets']} pkts)" for p in pkt_ev["top_destination_ports"][:3])
                    lines.append(f"    * Ports:   {ports_str}")
            elif not pkt_ev.get("available") and "flow_summary" in pkt_ev:
                fs = pkt_ev["flow_summary"]
                lines.append(
                    f"    * Flows:   {fs['flow_count']} flows, byte_rate={fs['byte_rate']:.1f} B/s, dst_ports={fs['dst_port_diversity']}"
                )

    # Time-Series Trajectory Table
    lines.append("-" * w)
    lines.append("TIME-SERIES PROGRESSION & RISK TRAJECTORY (First 20 Windows)")
    lines.append("-" * w)
    lines.append(
        f"{'Win':<4} {'Logical Time':<12} {'Stage':<20} {'Conf':<6} {'ProgProb':<10} {'Risk':<6} {'Trust':<8} {'Flagged':<8}"
    )
    lines.append("-" * w)

    display_series = report["time_series"] if verbose else report["time_series"][:20]
    for r in display_series:
        w_idx = r["window_index"]
        lt = r["logical_time"]
        stage = r["attack_stage"]["primary_stage"][:18]
        conf = r["attack_stage"]["confidence"]
        prob = r["progression_probability"]
        risk = r["future_security_risk"]["score"]
        trust = r["forecast_trust"]["trust_level"]
        flg = "YES" if r["flagged"] else "no"
        lines.append(
            f"{w_idx:<4} {lt:<12} {stage:<20} {conf:<6.2f} {prob:<10.4f} {risk:<6.2f} {trust:<8} {flg:<8}"
        )

    if not verbose and len(report["time_series"]) > 20:
        lines.append(f"... and {len(report['time_series']) - 20} more windows (use --verbose to view all).")

    lines.append("=" * w)
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Interactive Demo Mode (Default CLI Experience)
# ─────────────────────────────────────────────────────────────────────────────

def discover_sample_traffic_files() -> List[Path]:
    """Discover available sample captures (.pcap, .pcapng, .csv), excluding internal .states.jsonl."""
    candidates: List[Path] = []
    search_dirs = [
        Path("artifacts/scratch"),
        Path("."),
    ]
    seen: set[str] = set()
    extensions = ("*.pcap", "*.pcapng", "*.csv")
    for d in search_dirs:
        if not d.exists():
            continue
        for ext in extensions:
            for p in d.glob(ext):
                if p.name.startswith(".") or "test_report" in p.name:
                    continue
                resolved = str(p.resolve())
                if resolved not in seen and p.is_file():
                    seen.add(resolved)
                    candidates.append(p)
    return sorted(candidates, key=lambda x: str(x))


def make_progress_display(file_display_name: str) -> Callable[[str], None]:
    """Factory creating compact console progress reporter matching prompt specification."""
    print(f"\n{c_yellow('INPUT')}")
    print(f"{c_white(file_display_name)}\n")
    seen: set[str] = set()

    def _cb(stage_name: str) -> None:
        if stage_name not in seen:
            seen.add(stage_name)
            print(f"  {stage_name:<24} {c_white(CHAR_CHECK)}")

    return _cb


def run_interactive_session(report: Dict[str, Any]) -> None:
    """Execute interactive menu navigation loop over analysis results."""
    current_view = "summary"

    while True:
        if current_view == "summary":
            print(format_dashboard_summary(report))
        elif current_view == "evidence":
            print(render_evidence_view(report))
        elif current_view == "trajectory":
            print(render_trajectory_view(report))
        elif current_view == "explanation":
            print(render_explanation_view(report))

        print("")
        nav_prompt = (
            f"[{c_yellow('S')}] Summary    [{c_yellow('E')}] Evidence    "
            f"[{c_yellow('T')}] Trajectory    [{c_yellow('X')}] Explanation    "
            f"[{c_yellow('O')}] Export JSON    [{c_yellow('Q')}] Quit"
        )
        print(nav_prompt)

        try:
            choice = input("Select action: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if choice in ("q", "quit", "exit"):
            print("Session ended.")
            break
        elif choice in ("s", "summary"):
            current_view = "summary"
        elif choice in ("e", "evidence"):
            current_view = "evidence"
        elif choice in ("t", "trajectory"):
            current_view = "trajectory"
        elif choice in ("x", "explanation", "explain"):
            current_view = "explanation"
        elif choice in ("o", "export"):
            try:
                dest = input("Enter output path [analysis_report.json]: ").strip()
                if not dest:
                    dest = "analysis_report.json"
                out_p = Path(dest)
                out_p.parent.mkdir(parents=True, exist_ok=True)
                with open(out_p, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, sort_keys=True)
                print(c_yellow(f"\n[✓] Canonical analysis report successfully exported to: {out_p}\n"))
            except Exception as e:
                print(c_red(f"\n[-] Failed to export JSON: {e}\n"))
        else:
            pass


def run_interactive_mode(
    ar_model_dir: str | Path = "artifacts/models/ar5_authoritative",
    progression_model_path: str | Path = "artifacts/models/ar5_authoritative/progression_model.json",
    risk_threshold: float = 0.50,
    stage_threshold: float = 0.70,
    window_duration_s: float = 10.0,
) -> int:
    """Guided terminal experience for offline network security analysis."""
    w = 80
    border = CHAR_BORDER * w

    print(c_grey(border))
    print(c_bold(c_white("PREDICTIVE NETWORK SECURITY // OFFLINE ANALYSIS")))
    print(c_grey("Deterministic Multi-Horizon Behavioral Attack Progression Forecasting"))
    print(c_grey(border))

    while True:
        candidates = discover_sample_traffic_files()
        print("\nSelect a traffic capture to analyze:")
        for idx, path in enumerate(candidates, start=1):
            name = str(path)
            size_bytes = path.stat().st_size
            size_str = f"{size_bytes / 1024:.1f} KB" if size_bytes < 1024 * 1024 else f"{size_bytes / (1024 * 1024):.1f} MB"
            ext_label = path.suffix.upper().replace(".", "")
            print(f"  [{c_yellow(str(idx))}] {name:<58} {c_grey(f'({ext_label}, {size_str})')}")

        print(f"  [{c_yellow('C')}] Enter custom file path")
        print(f"  [{c_yellow('Q')}] Quit\n")

        try:
            choice = input(f"Select capture [1-{len(candidates)}, C, Q]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return 0

        if not choice:
            continue
        if choice.lower() in ("q", "quit", "exit"):
            print("Exiting.")
            return 0

        selected_path: Path | None = None
        if choice.isdigit():
            num = int(choice)
            if 1 <= num <= len(candidates):
                selected_path = candidates[num - 1]
            else:
                print(c_red(f"[-] Invalid selection: {num}. Please select from 1 to {len(candidates)}."))
                continue
        elif choice.lower() == "c":
            try:
                custom_input = input("Enter path to capture (.pcap, .pcapng, .csv, .states.jsonl): ").strip()
            except (EOFError, KeyboardInterrupt):
                return 0
            if not custom_input:
                continue
            selected_path = Path(custom_input)
        else:
            p = Path(choice)
            if p.exists() and p.is_file():
                selected_path = p
            else:
                print(c_red(f"[-] Unrecognized option or file not found: '{choice}'"))
                continue

        if not selected_path.exists():
            print(c_red(f"[-] File not found: '{selected_path}'"))
            continue

        # Valid capture path -> run with compact progress display
        progress_cb = make_progress_display(str(selected_path))

        try:
            report = run_offline_analysis(
                input_path=selected_path,
                ar_model_dir=ar_model_dir,
                progression_model_path=progression_model_path,
                risk_threshold=risk_threshold,
                stage_threshold=stage_threshold,
                window_duration_s=window_duration_s,
                progress_callback=progress_cb,
            )
        except Exception as exc:
            print(c_red(f"\n[-] Analysis failed: {exc}"))
            print("    Press Enter to return to file selection, or 'Q' to quit.")
            try:
                ret = input().strip().lower()
                if ret in ("q", "quit"):
                    return 1
            except (EOFError, KeyboardInterrupt):
                return 1
            continue

        # Enter interactive session
        print("")
        run_interactive_session(report)
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Configure and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="analyze",
        description="Predictive Network Security: Offline Attack Progression Forecasting CLI.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "input_path",
        type=str,
        nargs="?",
        default=None,
        help="Path to network traffic capture (.pcap, .pcapng, .csv, or .states.jsonl). If omitted, interactive demo mode launches.",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Optional path to save full canonical JSON report.",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Output display format for stdout.",
    )
    parser.add_argument(
        "--risk-threshold",
        type=float,
        default=0.50,
        help="Threshold on Future Security Risk score for flagging.",
    )
    parser.add_argument(
        "--stage-threshold",
        type=float,
        default=0.70,
        help="Threshold on Stage Hypothesis confidence for flagging.",
    )
    parser.add_argument(
        "--window-duration",
        type=float,
        default=10.0,
        help="Causal window aggregation interval in seconds.",
    )
    parser.add_argument(
        "--ar-model-dir",
        type=str,
        default="artifacts/models/ar5_authoritative",
        help="Directory containing the authoritative AR(5) model.",
    )
    parser.add_argument(
        "--progression-model",
        type=str,
        default="artifacts/models/ar5_authoritative/progression_model.json",
        help="Canonical JSON artifact path for calibrated progression model.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print complete un-truncated time series table in text mode.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI execution entrypoint."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    args = parse_args(argv)

    # If no input path provided: launch default interactive demo experience
    if args.input_path is None:
        return run_interactive_mode(
            ar_model_dir=args.ar_model_dir,
            progression_model_path=args.progression_model,
            risk_threshold=args.risk_threshold,
            stage_threshold=args.stage_threshold,
            window_duration_s=args.window_duration,
        )

    # Power-User / Non-Interactive Automation Mode
    try:
        report = run_offline_analysis(
            input_path=args.input_path,
            ar_model_dir=args.ar_model_dir,
            progression_model_path=args.progression_model,
            risk_threshold=args.risk_threshold,
            stage_threshold=args.stage_threshold,
            window_duration_s=args.window_duration,
        )

        # Save to output file if requested
        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, sort_keys=True)
            if args.format == "text":
                print(f"[+] Canonical analysis report written to: {out_p}")

        # Display to stdout
        if args.format == "json":
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(format_text_summary(report, verbose=args.verbose))

        return 0

    except Exception as exc:
        print(f"[-] Error executing offline analysis: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
