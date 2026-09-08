"""Auditable Day-2 CIC CSV -> NetworkState pipeline (no labels enter states)."""
from __future__ import annotations
import csv, hashlib, json, math
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from statistics import fmean, pstdev
from typing import Iterator

from core.config import Settings, load_settings
from core.contracts import FeatureAvailability, NetworkState, Source, STATE_FEATURES

REQUIRED = {"Timestamp", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Std", "SYN Flag Cnt", "ACK Flag Cnt", "RST Flag Cnt", "Pkt Len Mean", "Pkt Len Std", "Dst Port", "Protocol"}
NUMERIC = REQUIRED - {"Timestamp"}
TOPOLOGY = ("src_ip_diversity", "dst_ip_diversity", "src_port_diversity", "fan_out", "internal_ratio", "east_west_count")

@dataclass
class CleaningStats:
    rows_read: int = 0; rows_retained: int = 0; rows_removed: int = 0; repeated_headers_removed: int = 0
    malformed_rows: int = 0; timestamp_parse_failures: int = 0; numeric_invalid_rows: int = 0; nan_or_inf_rows: int = 0; duplicates_removed: int = 0
    nan_values_seen: int = 0; inf_values_seen: int = 0; rows_with_invalid_numeric_values: int = 0
    rows_removed_for_invalid_timestamp: int = 0; rows_removed_for_other_unrecoverable_reason: int = 0

@dataclass(frozen=True)
class Flow:
    timestamp: datetime; values: dict[str, float | None]; raw_hash: str

def _canonical(row: dict[str, str]) -> dict[str, str]: return {(k or "").strip(): (v or "").strip() for k, v in row.items()}
def _timestamp(value: str) -> datetime:
    # CIC exports are explicitly day-first; no locale inference is used.
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S.%f"):
        try: return datetime.strptime(value, fmt)
        except ValueError: pass
    raise ValueError(f"invalid day-first timestamp: {value!r}")

def read_flows(path: str | Path, stats: CleaningStats) -> Iterator[Flow]:
    """Stream rows, handle invalid numeric values at feature level, and never consume Label."""
    seen: set[str] = set()
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None: raise ValueError("CSV has no header")
        headers = {name.strip() for name in reader.fieldnames}
        missing = REQUIRED - headers
        if missing: raise ValueError(f"required CIC fields missing: {sorted(missing)}")
        for raw in reader:
            stats.rows_read += 1; row = _canonical(raw)
            if row.get("Timestamp") == "Timestamp":
                stats.repeated_headers_removed += 1; stats.rows_removed += 1; continue
            try:
                timestamp = _timestamp(row["Timestamp"])
            except (ValueError, KeyError):
                stats.timestamp_parse_failures += 1
                stats.rows_removed_for_invalid_timestamp += 1
                stats.rows_removed += 1
                continue

            values: dict[str, float | None] = {}
            row_has_invalid = False
            for key in NUMERIC:
                raw_val = row.get(key, "")
                try:
                    val = float(raw_val)
                    if math.isnan(val):
                        stats.nan_values_seen += 1
                        row_has_invalid = True
                        values[key] = None
                    elif math.isinf(val):
                        stats.inf_values_seen += 1
                        row_has_invalid = True
                        values[key] = None
                    else:
                        values[key] = val
                except (ValueError, TypeError):
                    stats.nan_values_seen += 1
                    row_has_invalid = True
                    values[key] = None

            if row_has_invalid:
                stats.rows_with_invalid_numeric_values += 1
                stats.nan_or_inf_rows += 1
                stats.numeric_invalid_rows += 1

            digest = hashlib.sha256(json.dumps({"Timestamp": row.get("Timestamp", ""), **{k: row.get(k, "") for k in sorted(NUMERIC)}}, sort_keys=True).encode()).hexdigest()
            if digest in seen:
                stats.duplicates_removed += 1; stats.rows_removed += 1; continue
            seen.add(digest); stats.rows_retained += 1
            yield Flow(timestamp, values, digest)

def _floor(ts: datetime, seconds: int) -> datetime:
    epoch = datetime(1970, 1, 1); return epoch + timedelta(seconds=int((ts - epoch).total_seconds() // seconds) * seconds)
def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""): digest.update(block)
    return digest.hexdigest()
def _skew(values: list[float]) -> float | None:
    if len(values) < 3: return None
    mean = fmean(values); std = pstdev(values)
    return 0.0 if std == 0 else fmean([(x - mean) ** 3 for x in values]) / std ** 3

def _state(start: datetime, rows: list[Flow], settings: Settings, session_id: str, gap_before: bool, gap_after: bool) -> NetworkState:
    end = start + timedelta(seconds=settings.window_size_seconds)
    provenance = hashlib.sha256("|".join(row.raw_hash for row in rows).encode()).hexdigest()
    unavailable = {name: FeatureAvailability.UNAVAILABLE for name in TOPOLOGY}
    window_id = f"{start.isoformat()}_{settings.window_size_seconds}s"
    if not rows:
        return NetworkState(
            window_id=window_id,
            timestamp_start=start,
            timestamp_end=end,
            window_duration_s=float(settings.window_size_seconds),
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
            source=Source.CSV,
            data_quality=0.0,
            is_empty=True,
            gap_before=gap_before,
            gap_after=gap_after,
            session_id=session_id,
            provenance_hash=provenance,
            feature_availability=unavailable,
        )

    get_valid = lambda name: [row.values[name] for row in rows if row.values.get(name) is not None]
    availability: dict[str, FeatureAvailability] = {name: FeatureAvailability.UNAVAILABLE for name in TOPOLOGY}
    
    flow_count = len(rows)
    availability["flow_count"] = FeatureAvailability.AVAILABLE

    fwd_bytes = get_valid("TotLen Fwd Pkts")
    bwd_bytes = get_valid("TotLen Bwd Pkts")
    if fwd_bytes or bwd_bytes:
        total_bytes = sum(fwd_bytes) + sum(bwd_bytes)
        byte_rate = total_bytes / settings.window_size_seconds
        availability["byte_rate"] = FeatureAvailability.AVAILABLE
    else:
        byte_rate = 0.0
        availability["byte_rate"] = FeatureAvailability.UNAVAILABLE

    fwd_pkts = get_valid("Tot Fwd Pkts")
    bwd_pkts = get_valid("Tot Bwd Pkts")
    if fwd_pkts or bwd_pkts:
        packet_total = sum(fwd_pkts) + sum(bwd_pkts)
        packet_rate = packet_total / settings.window_size_seconds
        availability["packet_rate"] = FeatureAvailability.AVAILABLE
    else:
        packet_total = 0.0
        packet_rate = 0.0
        availability["packet_rate"] = FeatureAvailability.UNAVAILABLE

    durations = get_valid("Flow Duration")
    if durations:
        mean_flow_duration = fmean(durations) / 1_000_000
        availability["mean_flow_duration"] = FeatureAvailability.AVAILABLE
    else:
        mean_flow_duration = 0.0
        availability["mean_flow_duration"] = FeatureAvailability.UNAVAILABLE

    dst_ports = get_valid("Dst Port")
    if dst_ports:
        dst_port_diversity = len(set(dst_ports))
        availability["dst_port_diversity"] = FeatureAvailability.AVAILABLE
    else:
        dst_port_diversity = 0
        availability["dst_port_diversity"] = FeatureAvailability.UNAVAILABLE

    syn_list = get_valid("SYN Flag Cnt")
    if syn_list:
        syn_count = int(sum(syn_list))
        availability["syn_count"] = FeatureAvailability.AVAILABLE
    else:
        syn_count = 0
        availability["syn_count"] = FeatureAvailability.UNAVAILABLE

    ack_list = get_valid("ACK Flag Cnt")
    if ack_list:
        ack_count = int(sum(ack_list))
        availability["ack_count"] = FeatureAvailability.AVAILABLE
    else:
        ack_count = 0
        availability["ack_count"] = FeatureAvailability.UNAVAILABLE

    rst_list = get_valid("RST Flag Cnt")
    if rst_list:
        rst_count = int(sum(rst_list))
        availability["rst_count"] = FeatureAvailability.AVAILABLE
    else:
        rst_count = 0
        availability["rst_count"] = FeatureAvailability.UNAVAILABLE

    if availability.get("syn_count") == FeatureAvailability.AVAILABLE and availability.get("packet_rate") == FeatureAvailability.AVAILABLE and packet_total > 0:
        syn_ratio = min(1.0, max(0.0, syn_count / packet_total))
        availability["syn_ratio"] = FeatureAvailability.AVAILABLE
    elif availability.get("syn_count") == FeatureAvailability.AVAILABLE and packet_total == 0:
        syn_ratio = 0.0
        availability["syn_ratio"] = FeatureAvailability.AVAILABLE
    else:
        syn_ratio = 0.0
        availability["syn_ratio"] = FeatureAvailability.UNAVAILABLE

    if availability.get("rst_count") == FeatureAvailability.AVAILABLE and availability.get("packet_rate") == FeatureAvailability.AVAILABLE and packet_total > 0:
        rst_ratio = min(1.0, max(0.0, rst_count / packet_total))
        availability["rst_ratio"] = FeatureAvailability.AVAILABLE
    elif availability.get("rst_count") == FeatureAvailability.AVAILABLE and packet_total == 0:
        rst_ratio = 0.0
        availability["rst_ratio"] = FeatureAvailability.AVAILABLE
    else:
        rst_ratio = 0.0
        availability["rst_ratio"] = FeatureAvailability.UNAVAILABLE

    iat_means = get_valid("Flow IAT Mean")
    if iat_means:
        iat_mean = fmean(iat_means) / 1_000_000
        iat_skew = _skew(iat_means)
        availability["iat_mean"] = FeatureAvailability.AVAILABLE
    else:
        iat_mean = 0.0
        iat_skew = None
        availability["iat_mean"] = FeatureAvailability.UNAVAILABLE

    iat_stds = get_valid("Flow IAT Std")
    if iat_stds:
        iat_std = fmean(iat_stds) / 1_000_000
        availability["iat_std"] = FeatureAvailability.AVAILABLE
    else:
        iat_std = 0.0
        availability["iat_std"] = FeatureAvailability.UNAVAILABLE

    pkt_means = get_valid("Pkt Len Mean")
    if pkt_means:
        pkt_size_mean = fmean(pkt_means)
        availability["pkt_size_mean"] = FeatureAvailability.AVAILABLE
    else:
        pkt_size_mean = 0.0
        availability["pkt_size_mean"] = FeatureAvailability.UNAVAILABLE

    pkt_stds = get_valid("Pkt Len Std")
    if pkt_stds:
        pkt_size_std = fmean(pkt_stds)
        availability["pkt_size_std"] = FeatureAvailability.AVAILABLE
    else:
        pkt_size_std = 0.0
        availability["pkt_size_std"] = FeatureAvailability.UNAVAILABLE

    flow_byte_totals = [r.values["TotLen Fwd Pkts"] + r.values["TotLen Bwd Pkts"] for r in rows if r.values.get("TotLen Fwd Pkts") is not None and r.values.get("TotLen Bwd Pkts") is not None]
    if len(flow_byte_totals) > 1:
        byte_variance = pstdev(flow_byte_totals) ** 2
        availability["byte_variance"] = FeatureAvailability.AVAILABLE
    elif len(flow_byte_totals) == 1:
        byte_variance = 0.0
        availability["byte_variance"] = FeatureAvailability.AVAILABLE
    else:
        byte_variance = 0.0
        availability["byte_variance"] = FeatureAvailability.UNAVAILABLE

    total_numeric_cells = len(rows) * len(NUMERIC)
    valid_numeric_cells = sum(1 for r in rows for k in NUMERIC if r.values.get(k) is not None)
    cell_ratio = valid_numeric_cells / total_numeric_cells if total_numeric_cells > 0 else 0.0

    expected_features = [name for name in STATE_FEATURES if name not in TOPOLOGY]
    avail_count = sum(1 for name in expected_features if availability.get(name) == FeatureAvailability.AVAILABLE)
    feature_ratio = avail_count / len(expected_features) if expected_features else 1.0

    data_quality = 1.0 if (cell_ratio == 1.0 and feature_ratio == 1.0) else max(0.01, min(1.0, cell_ratio * feature_ratio))

    return NetworkState(
        window_id=window_id,
        timestamp_start=start,
        timestamp_end=end,
        window_duration_s=float(settings.window_size_seconds),
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
        ttl_mean=None,
        ttl_variance=None,
        tcp_window_mean=None,
        fragment_count=None,
        retransmit_count=None,
        payload_size_mean=None,
        source=Source.CSV,
        data_quality=data_quality,
        is_empty=False,
        gap_before=gap_before,
        gap_after=gap_after,
        session_id=session_id,
        provenance_hash=provenance,
        feature_availability=availability,
    )

def build_states(path: str | Path, settings: Settings | None = None) -> tuple[list[NetworkState], CleaningStats]:
    settings = settings or load_settings(); stats = CleaningStats(); rows = sorted(read_flows(path, stats), key=lambda row: (row.timestamp, row.raw_hash))
    if stats.rows_read and stats.timestamp_parse_failures / stats.rows_read > settings.max_timestamp_failure_fraction: raise ValueError("timestamp failure rate exceeds configured threshold")
    if not rows: return [], stats
    buckets: dict[datetime, list[Flow]] = defaultdict(list)
    for row in rows: buckets[_floor(row.timestamp, settings.window_size_seconds)].append(row)
    starts: list[datetime] = []; current = min(buckets); last = max(buckets)
    while current <= last: starts.append(current); current += timedelta(seconds=settings.window_size_seconds)
    empty = [not buckets[start] for start in starts]; sessions: list[str] = []; session = 1; run = 0
    for is_empty in empty:
        if is_empty: run += 1
        else:
            if run * settings.window_size_seconds >= settings.long_gap_seconds: session += 1
            run = 0
        sessions.append(f"session-{session}")
    return [_state(start, buckets[start], settings, sessions[index], index > 0 and empty[index - 1], index < len(starts) - 1 and empty[index + 1]) for index, start in enumerate(starts)], stats

def _jsonable(state: NetworkState) -> dict:
    result = asdict(state); result["timestamp_start"] = state.timestamp_start.isoformat(); result["timestamp_end"] = state.timestamp_end.isoformat(); result["source"] = state.source.value; result["feature_availability"] = {k: v.value for k, v in state.feature_availability.items()}; return result
def write_artifacts(states: list[NetworkState], stats: CleaningStats, source_path: str | Path, output_dir: str | Path, settings: Settings | None = None) -> tuple[Path, Path]:
    settings = settings or load_settings(); output = Path(output_dir); output.mkdir(parents=True, exist_ok=True); source = Path(source_path)
    stem = source.stem; state_path = output / f"{stem}.states.jsonl"; manifest_path = output / f"{stem}.manifest.json"
    with open(state_path, "w", encoding="utf-8", newline="\n") as handle:
        for state in states: handle.write(json.dumps(_jsonable(state), sort_keys=True, separators=(",", ":")) + "\n")
    source_hash = _file_hash(source)
    manifest = {"pipeline_version": "day2-v1", "source_file": str(source), "source_sha256": source_hash, "state_schema_hash": __import__("core.contracts", fromlist=["STATE_SCHEMA_HASH"]).STATE_SCHEMA_HASH, "config": asdict(settings), "cleaning": asdict(stats), "state_count": len(states), "empty_window_count": sum(s.is_empty for s in states), "session_count": len(set(s.session_id for s in states)), "artifact_sha256": hashlib.sha256(state_path.read_bytes()).hexdigest()}
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return state_path, manifest_path
