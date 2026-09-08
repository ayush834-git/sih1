"""Dataset builder and chronological splitting for Delta-State baseline experiments."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Sequence

import numpy as np
from sklearn.preprocessing import RobustScaler

from core.contracts import FeatureAvailability, NetworkState, Source, STATE_FEATURES


# Features available in CSV source (excluding UNAVAILABLE topology fields)
CSV_AVAILABLE_FEATURES = [
    "flow_count",
    "byte_rate",
    "packet_rate",
    "mean_flow_duration",
    "dst_port_diversity",
    "syn_count",
    "ack_count",
    "rst_count",
    "syn_ratio",
    "rst_ratio",
    "iat_mean",
    "iat_std",
    "pkt_size_mean",
    "pkt_size_std",
    "byte_variance",
]

# 4 Observed Infiltration Blocks (as documented in MASTER_CONTEXT.md)
OBSERVED_INFILTRATION_BLOCKS = [
    {
        "block_id": "block-1-wed",
        "name": "Wednesday Block 1 (01:42 - 02:39)",
        "source_day": "Wednesday",
        "start": datetime(2018, 2, 28, 1, 42, 0),
        "end": datetime(2018, 2, 28, 2, 39, 0),
    },
    {
        "block_id": "block-2-wed",
        "name": "Wednesday Block 2 (10:50 - 12:04)",
        "source_day": "Wednesday",
        "start": datetime(2018, 2, 28, 10, 50, 0),
        "end": datetime(2018, 2, 28, 12, 4, 0),
    },
    {
        "block_id": "block-3-thu",
        "name": "Thursday Block 3 (02:00 - 03:36)",
        "source_day": "Thursday",
        "start": datetime(2018, 3, 1, 2, 0, 0),
        "end": datetime(2018, 3, 1, 3, 36, 0),
    },
    {
        "block_id": "block-4-thu",
        "name": "Thursday Block 4 (09:57 - 10:54)",
        "source_day": "Thursday",
        "start": datetime(2018, 3, 1, 9, 57, 0),
        "end": datetime(2018, 3, 1, 10, 54, 0),
    },
]


@dataclass(frozen=True)
class TransitionSample:
    """A single valid state transition with its historical context."""
    sample_id: str
    target_state_id: str
    target_start: datetime
    session_id: str
    feature_names: tuple[str, ...]
    history_states: tuple[dict[str, float], ...]  # [S_{t-h+1}, ..., S_t]
    current_state: dict[str, float]               # S_t
    next_state: dict[str, float]                  # S_{t+1}
    delta: dict[str, float]                       # S_{t+1} - S_t
    history_deltas: tuple[dict[str, float], ...]  # [ΔS_{t-h+1}, ..., ΔS_{t-1}]


def load_states_from_jsonl(path: str | Path) -> list[NetworkState]:
    """Load NetworkState objects from a .states.jsonl artifact file."""
    states: list[NetworkState] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            data = json.loads(line)
            availability = {
                k: FeatureAvailability(v)
                for k, v in data.get("feature_availability", {}).items()
            }
            state = NetworkState(
                window_id=data["window_id"],
                timestamp_start=datetime.fromisoformat(data["timestamp_start"]),
                timestamp_end=datetime.fromisoformat(data["timestamp_end"]),
                window_duration_s=float(data["window_duration_s"]),
                flow_count=int(data["flow_count"]),
                byte_rate=float(data["byte_rate"]),
                packet_rate=float(data["packet_rate"]),
                mean_flow_duration=float(data["mean_flow_duration"]),
                src_ip_diversity=data.get("src_ip_diversity"),
                dst_ip_diversity=data.get("dst_ip_diversity"),
                src_port_diversity=data.get("src_port_diversity"),
                dst_port_diversity=int(data["dst_port_diversity"]),
                fan_out=data.get("fan_out"),
                internal_ratio=data.get("internal_ratio"),
                east_west_count=data.get("east_west_count"),
                syn_count=int(data["syn_count"]),
                ack_count=int(data["ack_count"]),
                rst_count=int(data["rst_count"]),
                syn_ratio=float(data["syn_ratio"]),
                rst_ratio=float(data["rst_ratio"]),
                iat_mean=float(data["iat_mean"]),
                iat_std=float(data["iat_std"]),
                iat_skew=data.get("iat_skew"),
                pkt_size_mean=float(data["pkt_size_mean"]),
                pkt_size_std=float(data["pkt_size_std"]),
                byte_variance=float(data["byte_variance"]),
                ttl_mean=data.get("ttl_mean"),
                ttl_variance=data.get("ttl_variance"),
                tcp_window_mean=data.get("tcp_window_mean"),
                fragment_count=data.get("fragment_count"),
                retransmit_count=data.get("retransmit_count"),
                payload_size_mean=data.get("payload_size_mean"),
                source=Source(data["source"]),
                data_quality=float(data["data_quality"]),
                is_empty=bool(data["is_empty"]),
                gap_before=bool(data["gap_before"]),
                gap_after=bool(data["gap_after"]),
                session_id=data["session_id"],
                provenance_hash=data["provenance_hash"],
                feature_availability=availability,
            )
            states.append(state)
    return states


def extract_transitions(
    states: Sequence[NetworkState],
    history_depth: int = 3,
    feature_names: Sequence[str] | None = None,
) -> tuple[list[TransitionSample], dict[str, int]]:
    """
    Extract valid transitions [S_{t-h+1}, ..., S_t] -> ΔS_t = S_{t+1} - S_t.
    
    Strict rules:
    - Never bridge an empty window
    - Never cross a session boundary
    - Never bridge a temporal gap
    - Only use features present in feature_values()
    """
    if history_depth < 1:
        raise ValueError("history_depth must be >= 1")
    
    if feature_names is None:
        feature_names = tuple(CSV_AVAILABLE_FEATURES)
    else:
        feature_names = tuple(feature_names)
        
    samples: list[TransitionSample] = []
    dropped_counts: dict[str, int] = {
        "empty_state_in_window": 0,
        "session_boundary_crossed": 0,
        "time_gap_encountered": 0,
        "unavailable_feature": 0,
    }

    # We need a contiguous window of length (history_depth + 1):
    # [S_{t-h+1}, ..., S_t, S_{t+1}]
    window_len = history_depth + 1
    
    for i in range(len(states) - window_len + 1):
        window = states[i : i + window_len]
        
        # Check empty states
        if any(s.is_empty for s in window):
            dropped_counts["empty_state_in_window"] += 1
            continue
            
        # Check session consistency
        sessions = {s.session_id for s in window}
        if len(sessions) > 1:
            dropped_counts["session_boundary_crossed"] += 1
            continue
            
        # Check time continuity (each step must be exactly window_duration_s)
        time_valid = True
        for k in range(len(window) - 1):
            if window[k].timestamp_end != window[k + 1].timestamp_start:
                time_valid = False
                break
        if not time_valid:
            dropped_counts["time_gap_encountered"] += 1
            continue
            
        # Check feature availability in all window states
        feature_valid = True
        state_feature_dicts = []
        for s in window:
            fvals = s.feature_values()
            if not all(f in fvals for f in feature_names):
                feature_valid = False
                break
            state_feature_dicts.append({f: fvals[f] for f in feature_names})
        if not feature_valid:
            dropped_counts["unavailable_feature"] += 1
            continue
            
        # Extract history states: S_{t-h+1} ... S_t
        h_states = tuple(state_feature_dicts[:-1])
        curr_state = state_feature_dicts[-2]
        next_state = state_feature_dicts[-1]
        
        # Compute target delta: ΔS_t = S_{t+1} - S_t
        target_delta = {f: next_state[f] - curr_state[f] for f in feature_names}
        
        # Compute historical deltas: ΔS_k = S_{k+1} - S_k for k in t-h+1 .. t-1
        h_deltas = tuple(
            {f: h_states[k + 1][f] - h_states[k][f] for f in feature_names}
            for k in range(len(h_states) - 1)
        )
        
        target_s = window[-1]
        sample = TransitionSample(
            sample_id=f"{window[-2].window_id}_to_{target_s.window_id}",
            target_state_id=target_s.window_id,
            target_start=target_s.timestamp_start,
            session_id=window[-2].session_id,
            feature_names=feature_names,
            history_states=h_states,
            current_state=curr_state,
            next_state=next_state,
            delta=target_delta,
            history_deltas=h_deltas,
        )
        samples.append(sample)
        
    return samples, dropped_counts


@dataclass
class DatasetArrays:
    """Numpy feature matrices and delta targets for training/evaluation."""
    X: np.ndarray              # Shape: (N, history_depth * n_features) - flattened history
    y: np.ndarray              # Shape: (N, n_features) - ΔS_t target
    X_deltas: np.ndarray       # Shape: (N, (history_depth - 1) * n_features) - historical deltas
    current_states: np.ndarray # Shape: (N, n_features) - S_t
    next_states: np.ndarray    # Shape: (N, n_features) - S_{t+1}
    timestamps: list[datetime]
    sample_ids: list[str]
    feature_names: list[str]


def samples_to_arrays(samples: Sequence[TransitionSample]) -> DatasetArrays:
    """Convert a sequence of TransitionSample objects into structured numpy arrays."""
    if not samples:
        raise ValueError("Cannot convert empty sample list to arrays")
        
    feature_names = list(samples[0].feature_names)
    n_features = len(feature_names)
    h_depth = len(samples[0].history_states)
    n_samples = len(samples)
    
    X = np.zeros((n_samples, h_depth * n_features), dtype=np.float64)
    y = np.zeros((n_samples, n_features), dtype=np.float64)
    
    n_hist_deltas = len(samples[0].history_deltas)
    X_deltas = np.zeros((n_samples, max(1, n_hist_deltas) * n_features), dtype=np.float64)
    current_states = np.zeros((n_samples, n_features), dtype=np.float64)
    next_states = np.zeros((n_samples, n_features), dtype=np.float64)
    
    timestamps = []
    sample_ids = []
    
    for i, s in enumerate(samples):
        # Flatten history states: [S_{t-h+1}, ..., S_t]
        h_vec = []
        for state_dict in s.history_states:
            for f in feature_names:
                h_vec.append(state_dict[f])
        X[i, :] = h_vec
        
        # Target delta: ΔS_t
        y[i, :] = [s.delta[f] for f in feature_names]
        
        # History deltas
        if n_hist_deltas > 0:
            d_vec = []
            for delta_dict in s.history_deltas:
                for f in feature_names:
                    d_vec.append(delta_dict[f])
            X_deltas[i, :] = d_vec
            
        current_states[i, :] = [s.current_state[f] for f in feature_names]
        next_states[i, :] = [s.next_state[f] for f in feature_names]
        timestamps.append(s.target_start)
        sample_ids.append(s.sample_id)
        
    return DatasetArrays(
        X=X,
        y=y,
        X_deltas=X_deltas,
        current_states=current_states,
        next_states=next_states,
        timestamps=timestamps,
        sample_ids=sample_ids,
        feature_names=feature_names,
    )


def chronological_split(
    samples: Sequence[TransitionSample],
    train_ratio: float = 0.60,
    val_ratio: float = 0.15,
    test_ratio: float = 0.25,
) -> tuple[list[TransitionSample], list[TransitionSample], list[TransitionSample]]:
    """
    Strict chronological split (default: 60% train, 15% val, 25% test).
    Splits per session or across overall chronologically sorted samples.
    """
    total = len(samples)
    if total < 10:
        raise ValueError(f"Too few samples ({total}) for a 3-way split")
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6
    
    sorted_samples = sorted(samples, key=lambda s: s.target_start)
    n_train = int(round(total * train_ratio))
    n_val = int(round(total * val_ratio))
    
    train_samples = sorted_samples[:n_train]
    val_samples = sorted_samples[n_train : n_train + n_val]
    test_samples = sorted_samples[n_train + n_val :]
    
    return train_samples, val_samples, test_samples


def leave_one_block_out_split(
    samples: Sequence[TransitionSample],
    block: dict,
) -> tuple[list[TransitionSample], list[TransitionSample], list[TransitionSample]]:
    """
    Split for Leave-One-Observed-Infiltration-Block-Out.
    - Test: Transitions whose target start is within [block['start'], block['end']]
    - Eligible non-test transitions: split 80% train / 20% val chronologically.
    """
    start_dt, end_dt = block["start"], block["end"]
    
    test_samples = [s for s in samples if start_dt <= s.target_start <= end_dt]
    other_samples = [s for s in samples if not (start_dt <= s.target_start <= end_dt)]
    
    other_sorted = sorted(other_samples, key=lambda s: s.target_start)
    n_other = len(other_sorted)
    n_train = int(round(n_other * 0.80))
    
    train_samples = other_sorted[:n_train]
    val_samples = other_sorted[n_train:]
    
    return train_samples, val_samples, test_samples
