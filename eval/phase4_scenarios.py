"""Controlled Evaluation Scenarios for Phase 4 (SIH 26153).

Provides 12 standardized progression scenarios across four categories:
1. Reconnaissance (Slow scan, Stepping stone, Rapid probe)
2. Denial of Service (Gradual ramp, Connection exhaustion, Volumetric flood)
3. Exfiltration (DNS tunneling, Volumetric TCP, Burst web transfer)
4. Benign Stress & Ambiguous Noise (Backup surge, Flash crowd, Background noise)

Each scenario produces a deterministic sequence of schema-compliant NetworkState objects.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Mapping, Sequence

import numpy as np

from core.contracts import FeatureAvailability, NetworkState, Source
from eval.dataset import CSV_AVAILABLE_FEATURES
from scenarios.demo.scenarios import create_demo_state


@dataclass(frozen=True)
class Phase4EventDefinition:
    """Ground truth event definition for a scenario class."""
    event_name: str
    target_stage: str
    condition_description: str
    min_sustained_windows: int
    relevant_action: str
    action_duration_s: int
    condition_fn: Callable[[NetworkState], bool]


PHASE4_EVENT_DEFINITIONS: Mapping[str, Phase4EventDefinition] = {
    "Reconnaissance": Phase4EventDefinition(
        event_name="Sustained Reconnaissance Exploration",
        target_stage="Reconnaissance",
        condition_description="dst_port_diversity >= 20 for >= 2 consecutive 10s windows",
        min_sustained_windows=2,
        relevant_action="RATE_LIMIT_IP",
        action_duration_s=20,
        condition_fn=lambda s: (getattr(s, "dst_port_diversity", 0) or 0) >= 20,
    ),
    "Impact / Denial of Service": Phase4EventDefinition(
        event_name="Sustained Connection Flooding / DoS",
        target_stage="Impact / Denial of Service",
        condition_description="flow_count >= 200 and rst_ratio >= 0.25 for >= 2 consecutive 10s windows",
        min_sustained_windows=2,
        relevant_action="RATE_LIMIT_IP",
        action_duration_s=20,
        condition_fn=lambda s: ((getattr(s, "flow_count", 0) or 0) >= 200 and
                                (getattr(s, "rst_ratio", 0.0) or 0.0) >= 0.25),
    ),
    "Collection / Exfiltration": Phase4EventDefinition(
        event_name="Sustained Volumetric Outbound Exfiltration",
        target_stage="Collection / Exfiltration",
        condition_description="byte_rate >= 100,000 B/s for >= 2 consecutive 10s windows",
        min_sustained_windows=2,
        relevant_action="RATE_LIMIT_IP",
        action_duration_s=20,
        condition_fn=lambda s: (getattr(s, "byte_rate", 0.0) or 0.0) >= 100000.0,
    ),
}


def build_phase4_scenarios(
    start_time: datetime | None = None,
    seed: int = 42,
    noise_level: float = 0.0,
) -> dict[str, list[NetworkState]]:
    """
    Construct the 12 standard Phase 4 evaluation scenarios.
    Returns mapping of scenario_id -> list of NetworkState (length 8 to 10 windows).
    When noise_level > 0, applies controlled stochastic perturbations to telemetry values.
    """
    t0 = start_time or datetime(2026, 9, 8, 12, 0, 0)
    rng = np.random.RandomState(seed)

    def perturb(val: float, is_int: bool = False, min_val: float = 0.0) -> float:
        if noise_level <= 0.0 or val == 0.0:
            return val
        scale = 1.0 + rng.uniform(-noise_level, noise_level)
        out = max(min_val, val * scale)
        return int(round(out)) if is_int else float(out)

    scenarios: dict[str, list[NetworkState]] = {}

    # =========================================================================
    # Category 1: Reconnaissance Progressions
    # =========================================================================

    # 1. Slow Port Scan: Sub-threshold incremental port diversity drift
    s1: list[NetworkState] = []
    p_divs = [2, 3, 3, 5, 8, 14, 22, 34, 48, 60]
    flows = [10, 11, 12, 14, 18, 25, 45, 70, 95, 120]
    for w, (p, f) in enumerate(zip(p_divs, flows)):
        p_val = perturb(p, is_int=True, min_val=1)
        f_val = perturb(f, is_int=True, min_val=1)
        s1.append(create_demo_state(w, t0, dst_port_diversity=p_val, flow_count=f_val, syn_ratio=0.15))
    scenarios["recon_slow_port_scan"] = s1

    # 2. Stepping-Stone Probe: Multi-target horizontal discovery
    s2: list[NetworkState] = []
    p_divs_2 = [2, 2, 3, 4, 12, 25, 38, 52, 65]
    flows_2 = [10, 12, 15, 20, 45, 85, 130, 175, 210]
    for w, (p, f) in enumerate(zip(p_divs_2, flows_2)):
        p_val = perturb(p, is_int=True, min_val=1)
        f_val = perturb(f, is_int=True, min_val=1)
        s2.append(create_demo_state(w, t0, dst_port_diversity=p_val, flow_count=f_val, syn_ratio=0.25))
    scenarios["recon_stepping_stone"] = s2

    # 3. Rapid SYN Probe: Fast volumetric probe
    s3: list[NetworkState] = []
    p_divs_3 = [2, 2, 2, 15, 35, 55, 75, 95]
    syn_3 = [0.05, 0.05, 0.06, 0.30, 0.55, 0.70, 0.80, 0.85]
    for w, (p, syn) in enumerate(zip(p_divs_3, syn_3)):
        p_val = perturb(p, is_int=True, min_val=1)
        f_val = perturb(20 + w * 15, is_int=True, min_val=1)
        syn_val = min(1.0, perturb(syn, is_int=False, min_val=0.01))
        s3.append(create_demo_state(w, t0, dst_port_diversity=p_val, flow_count=f_val, syn_ratio=syn_val))
    scenarios["recon_rapid_syn_probe"] = s3

    # =========================================================================
    # Category 2: Denial of Service Progressions
    # =========================================================================

    # 4. Gradual SYN Ramp: Steady connection flood ramp-up
    s4: list[NetworkState] = []
    flows_4 = [15, 18, 20, 25, 90, 220, 360, 500, 650]
    rst_4 = [0.01, 0.02, 0.01, 0.02, 0.15, 0.30, 0.38, 0.42, 0.45]
    for w, (f, rst) in enumerate(zip(flows_4, rst_4)):
        f_val = perturb(f, is_int=True, min_val=1)
        rst_val = min(1.0, perturb(rst, is_int=False, min_val=0.005))
        s4.append(create_demo_state(w, t0, flow_count=f_val, packet_rate=f_val * 4.0, rst_ratio=rst_val, syn_ratio=0.35))
    scenarios["dos_gradual_syn_ramp"] = s4

    # 5. Connection Exhaustion: Sharp high-volume connection flood
    s5: list[NetworkState] = []
    flows_5 = [20, 22, 25, 180, 420, 750, 1100, 1500]
    rst_5 = [0.01, 0.01, 0.02, 0.26, 0.36, 0.45, 0.50, 0.52]
    for w, (f, rst) in enumerate(zip(flows_5, rst_5)):
        f_val = perturb(f, is_int=True, min_val=1)
        rst_val = min(1.0, perturb(rst, is_int=False, min_val=0.005))
        s5.append(create_demo_state(w, t0, flow_count=f_val, packet_rate=f_val * 5.0, rst_ratio=rst_val, syn_ratio=0.45))
    scenarios["dos_connection_exhaustion"] = s5

    # 6. Volumetric UDP / Packet Flood: High packet rate surge
    s6: list[NetworkState] = []
    pkts_6 = [30.0, 35.0, 40.0, 280.0, 850.0, 1600.0, 2400.0, 3200.0]
    bytes_6 = [2000.0, 2200.0, 2500.0, 25000.0, 95000.0, 180000.0, 270000.0, 360000.0]
    for w, (p, b) in enumerate(zip(pkts_6, bytes_6)):
        p_val = perturb(p, is_int=False, min_val=1.0)
        b_val = perturb(b, is_int=False, min_val=100.0)
        s6.append(create_demo_state(w, t0, packet_rate=p_val, byte_rate=b_val, flow_count=int(p_val / 3.0), rst_ratio=0.28))
    scenarios["dos_volumetric_udp_flood"] = s6

    # =========================================================================
    # Category 3: Collection / Exfiltration Progressions
    # =========================================================================

    # 7. DNS Tunneling: Low byte-rate, high query diversity
    s7: list[NetworkState] = []
    bytes_7 = [2000.0, 2200.0, 2500.0, 3000.0, 15000.0, 45000.0, 85000.0, 125000.0, 180000.0]
    p_divs_7 = [2, 2, 3, 3, 8, 15, 22, 28, 35]
    for w, (b, p) in enumerate(zip(bytes_7, p_divs_7)):
        b_val = perturb(b, is_int=False, min_val=100.0)
        p_val = perturb(p, is_int=True, min_val=1)
        s7.append(create_demo_state(w, t0, byte_rate=b_val, dst_port_diversity=p_val, pkt_size_mean=350.0))
    scenarios["exfil_dns_tunneling"] = s7

    # 8. Volumetric TCP Exfiltration: Large bulk file transfer
    s8: list[NetworkState] = []
    bytes_8 = [2000.0, 2500.0, 2200.0, 3000.0, 35000.0, 120000.0, 250000.0, 400000.0]
    pkts_8 = [120.0, 130.0, 125.0, 140.0, 400.0, 650.0, 800.0, 920.0]
    for w, (b, ps) in enumerate(zip(bytes_8, pkts_8)):
        b_val = perturb(b, is_int=False, min_val=100.0)
        ps_val = perturb(ps, is_int=False, min_val=50.0)
        s8.append(create_demo_state(w, t0, byte_rate=b_val, pkt_size_mean=ps_val, packet_rate=b_val / max(1.0, ps_val)))
    scenarios["exfil_volumetric_tcp"] = s8

    # 9. Burst Web Exfiltration: Periodic outbound surge
    s9: list[NetworkState] = []
    bytes_9 = [2000.0, 2200.0, 2400.0, 28000.0, 110000.0, 240000.0, 380000.0, 520000.0]
    for w, b in enumerate(bytes_9):
        b_val = perturb(b, is_int=False, min_val=100.0)
        s9.append(create_demo_state(w, t0, byte_rate=b_val, pkt_size_mean=700.0, packet_rate=b_val / 700.0))
    scenarios["exfil_burst_web"] = s9

    # =========================================================================
    # Category 4: Benign Stress & Ambiguous Noise (No sustained attack events)
    # =========================================================================

    # 10. Benign Backup Surge: 1-window batch backup burst that rapidly subsides
    s10: list[NetworkState] = []
    bytes_10 = [2000.0, 2500.0, 2200.0, 3000.0, 85000.0, 4000.0, 2800.0, 2200.0]
    for w, b in enumerate(bytes_10):
        b_val = perturb(b, is_int=False, min_val=100.0)
        s10.append(create_demo_state(w, t0, flow_count=15, byte_rate=b_val, syn_ratio=0.04, rst_ratio=0.01))
    scenarios["benign_backup_surge"] = s10

    # 11. Benign Flash Crowd: Rapid user influx with legitimate TCP flags
    s11: list[NetworkState] = []
    flows_11 = [15, 18, 22, 28, 75, 140, 160, 145, 110, 80]
    bytes_11 = [2000.0, 2400.0, 3000.0, 4200.0, 15000.0, 35000.0, 45000.0, 40000.0, 28000.0, 18000.0]
    for w, (f, b) in enumerate(zip(flows_11, bytes_11)):
        f_val = perturb(f, is_int=True, min_val=1)
        b_val = perturb(b, is_int=False, min_val=100.0)
        s11.append(create_demo_state(w, t0, flow_count=f_val, byte_rate=b_val, syn_ratio=0.03, rst_ratio=0.01))
    scenarios["benign_flash_crowd"] = s11

    # 12. Ambiguous Background Noise: Random jitter within safe baseline
    s12: list[NetworkState] = []
    for w in range(8):
        jitter_p = int(3 + rng.uniform(0, 4))
        jitter_f = int(12 + rng.uniform(0, 10))
        jitter_b = float(1500.0 + rng.uniform(0, 2500.0))
        p_val = perturb(jitter_p, is_int=True, min_val=1)
        f_val = perturb(jitter_f, is_int=True, min_val=1)
        b_val = perturb(jitter_b, is_int=False, min_val=500.0)
        s12.append(create_demo_state(w, t0, dst_port_diversity=p_val, flow_count=f_val, byte_rate=b_val))
    scenarios["benign_ambiguous_noise"] = s12

    return scenarios


def build_phase4_episodes(
    start_time: datetime | None = None,
    n_repetitions: int = 20,
    base_seed: int = 42,
    noise_level: float = 0.05,
) -> dict[str, Any]:
    """
    Construct the full hierarchical evaluation suite:
    12 standardized scenario templates x n_repetitions stochastic realizations = 240 evaluation episodes.
    Returns dictionary containing episode records, template metadata, and aggregation parameters.
    """
    category_map = {
        "recon_slow_port_scan": ("Reconnaissance", "Reconnaissance"),
        "recon_stepping_stone": ("Reconnaissance", "Reconnaissance"),
        "recon_rapid_syn_probe": ("Reconnaissance", "Reconnaissance"),
        "dos_gradual_syn_ramp": ("Denial of Service", "Impact / Denial of Service"),
        "dos_connection_exhaustion": ("Denial of Service", "Impact / Denial of Service"),
        "dos_volumetric_udp_flood": ("Denial of Service", "Impact / Denial of Service"),
        "exfil_dns_tunneling": ("Collection / Exfiltration", "Collection / Exfiltration"),
        "exfil_volumetric_tcp": ("Collection / Exfiltration", "Collection / Exfiltration"),
        "exfil_burst_web": ("Collection / Exfiltration", "Collection / Exfiltration"),
        "benign_backup_surge": ("Benign Stress", None),
        "benign_flash_crowd": ("Benign Stress", None),
        "benign_ambiguous_noise": ("Benign Ambiguity", None),
    }

    template_ids = list(category_map.keys())
    episodes: list[dict[str, Any]] = []

    for rep_idx in range(n_repetitions):
        rep_seed = base_seed + rep_idx * 1000
        # rep 0 is the baseline without noise; subsequent reps apply noise
        scenarios_rep = build_phase4_scenarios(
            start_time=start_time,
            seed=rep_seed,
            noise_level=0.0 if rep_idx == 0 else noise_level,
        )

        for tmpl_id in template_ids:
            states = scenarios_rep[tmpl_id]
            macro_cat, onset_cat = category_map[tmpl_id]
            episodes.append({
                "episode_id": f"{tmpl_id}_rep{rep_idx:02d}",
                "template_id": tmpl_id,
                "repetition_index": rep_idx,
                "seed": rep_seed,
                "states": states,
                "macro_category": macro_cat,
                "onset_category": onset_cat,
                "is_attack": onset_cat is not None,
                "length_windows": len(states),
            })

    return {
        "template_ids": template_ids,
        "n_templates": len(template_ids),
        "n_repetitions": n_repetitions,
        "total_episodes": len(episodes),
        "base_seed": base_seed,
        "noise_level": noise_level,
        "episodes": episodes,
    }
