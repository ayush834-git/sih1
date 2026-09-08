"""Ground-truth attack timeline, supervised stage mapping, and transition labeling (SIH 26153)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Sequence, Tuple

from eval.dataset import OBSERVED_INFILTRATION_BLOCKS, TransitionSample


# Formal MITRE ATT&CK Stage Definitions for CSE-CIC-IDS2018 Infiltration
STAGE_BENIGN = "BENIGN"
STAGE_RECONNAISSANCE = "RECONNAISSANCE"
STAGE_INFILTRATION = "EXPLOITATION_INFILTRATION"
STAGE_LATERAL_EXFIL = "LATERAL_EXFILTRATION"
STAGE_IMPACT = "IMPACT_DOS"

# Official MITRE ATT&CK Tactic and Technique Mappings
# Conflation Guard: Attack family != Attack stage != ATT&CK tactic != ATT&CK technique
MITRE_ATTACK_TAXONOMY: dict[str, dict[str, str | list[dict[str, str]]]] = {
    STAGE_BENIGN: {
        "tactic": "None",
        "technique_id": "None",
        "technique_name": "Normal Operations",
    },
    STAGE_RECONNAISSANCE: {
        "tactic": "Reconnaissance (TA0043)",
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
    },
    STAGE_INFILTRATION: {
        "tactic": "Initial Access (TA0001)",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
    },
    STAGE_LATERAL_EXFIL: {
        "tactic": "Lateral Movement (TA0008) / Exfiltration (TA0010)",
        "technique_id": "T1021, T1048",
        "technique_name": "Remote Services / Exfiltration Over Alternative Protocol",
    },
    STAGE_IMPACT: {
        "tactic": "Impact (TA0040)",
        "technique_id": "T1499",
        "technique_name": "Endpoint DoS",
    },
}

# Transition Types
TRANSITION_STEADY_BENIGN = "STEADY_BENIGN"
TRANSITION_ATTACK_ONSET = "ATTACK_ONSET"           # 0 -> 1 (Forecasting target)
TRANSITION_ATTACK_ACTIVE = "ATTACK_ACTIVE"         # 1 -> 1
TRANSITION_ATTACK_CESSATION = "ATTACK_CESSATION"   # 1 -> 0



@dataclass(frozen=True)
class AttackInterval:
    """A verified contiguous time range representing an active attack."""
    interval_id: str
    attack_family: str       # "Infiltration" or "DDoS"
    start_time: datetime
    end_time: datetime
    recon_duration_s: float = 600.0   # Initial reconnaissance phase (e.g. 10 mins)


# Default verified attack intervals from dataset ground truth
KNOWN_ATTACK_INTERVALS = [
    AttackInterval(
        interval_id=b["block_id"],
        attack_family="Infiltration",
        start_time=b["start"],
        end_time=b["end"],
        recon_duration_s=600.0,
    )
    for b in OBSERVED_INFILTRATION_BLOCKS
]

# Wednesday-21 DDoS intervals
DDOS_INTERVALS_WED21 = [
    AttackInterval(
        interval_id="ddos-wed21-loic",
        attack_family="DDoS",
        start_time=datetime(2018, 2, 21, 10, 8, 50),
        end_time=datetime(2018, 2, 21, 10, 45, 0),
        recon_duration_s=120.0,
    ),
    AttackInterval(
        interval_id="ddos-wed21-hoic",
        attack_family="DDoS",
        start_time=datetime(2018, 2, 21, 12, 0, 0),
        end_time=datetime(2018, 2, 21, 14, 30, 0),
        recon_duration_s=180.0,
    ),
]


def is_timestamp_in_attack(
    ts: datetime,
    intervals: Sequence[AttackInterval] = KNOWN_ATTACK_INTERVALS,
) -> Tuple[bool, AttackInterval | None]:
    """Check if a timestamp falls within any known attack interval."""
    for iv in intervals:
        if iv.start_time <= ts <= iv.end_time:
            return True, iv
    return False, None


def get_mitre_stage_for_timestamp(
    ts: datetime,
    intervals: Sequence[AttackInterval] = KNOWN_ATTACK_INTERVALS,
) -> str:
    """Map a timestamp to its MITRE ATT&CK progression stage."""
    in_attack, iv = is_timestamp_in_attack(ts, intervals)
    if not in_attack or iv is None:
        return STAGE_BENIGN

    offset = (ts - iv.start_time).total_seconds()
    if iv.attack_family == "DDoS":
        if offset < iv.recon_duration_s:
            return STAGE_RECONNAISSANCE
        return STAGE_IMPACT

    # Infiltration multi-stage progression
    total_duration = (iv.end_time - iv.start_time).total_seconds()
    if offset < iv.recon_duration_s:
        return STAGE_RECONNAISSANCE
    elif offset < (total_duration * 0.50):
        return STAGE_INFILTRATION
    else:
        return STAGE_LATERAL_EXFIL


@dataclass(frozen=True)
class LabeledTransition:
    """A TransitionSample enriched with ground truth attack timeline annotations."""
    sample: TransitionSample
    current_is_attack: int           # 0 or 1
    next_is_attack: int              # 0 or 1
    current_stage: str
    next_stage: str
    transition_type: str             # STEADY_BENIGN, ATTACK_ONSET, ATTACK_ACTIVE, ATTACK_CESSATION
    steps_to_next_onset: int         # -1 if no onset within window, else count of steps
    lookahead_attack_h1: int         # 1 if next_state is attack
    lookahead_attack_h2: int         # 1 if attack in [t+1, t+2]
    lookahead_attack_h3: int         # 1 if attack in [t+1, t+3]


def annotate_transitions(
    transitions: Sequence[TransitionSample],
    intervals: Sequence[AttackInterval] = KNOWN_ATTACK_INTERVALS,
) -> List[LabeledTransition]:
    """Derive ground-truth supervised labels for a sequence of TransitionSample objects.
    
    Generates:
    - current_is_attack / next_is_attack binary indicators
    - current_stage / next_stage MITRE progression stages
    - transition_type (STEADY_BENIGN, ATTACK_ONSET, etc.)
    - lookahead_attack targets across multi-step horizons (h=1, 2, 3)
    """
    sorted_trans = sorted(transitions, key=lambda s: s.target_start)
    labeled: List[LabeledTransition] = []

    # Map target_start to attack status
    trans_attack_status: List[bool] = []
    for s in sorted_trans:
        in_att, _ = is_timestamp_in_attack(s.target_start, intervals)
        trans_attack_status.append(in_att)

    for i, s in enumerate(sorted_trans):
        # Current state timestamp is target_start - 10s
        t_current = s.target_start - timedelta(seconds=10)
        curr_is_att, _ = is_timestamp_in_attack(t_current, intervals)
        next_is_att = trans_attack_status[i]

        curr_stage = get_mitre_stage_for_timestamp(t_current, intervals)
        next_stage = get_mitre_stage_for_timestamp(s.target_start, intervals)

        if not curr_is_att and not next_is_att:
            ttype = TRANSITION_STEADY_BENIGN
        elif not curr_is_att and next_is_att:
            ttype = TRANSITION_ATTACK_ONSET
        elif curr_is_att and next_is_att:
            ttype = TRANSITION_ATTACK_ACTIVE
        else:
            ttype = TRANSITION_ATTACK_CESSATION

        # Lookahead attack manifestation indicators for horizons h=1..3
        h1 = 1 if next_is_att else 0
        h2 = 1 if (h1 or (i + 1 < len(trans_attack_status) and trans_attack_status[i + 1])) else 0
        h3 = 1 if (h2 or (i + 2 < len(trans_attack_status) and trans_attack_status[i + 2])) else 0

        # Steps to next onset
        steps_to_onset = -1
        for k in range(i, min(i + 30, len(sorted_trans))):
            in_att_k, _ = is_timestamp_in_attack(sorted_trans[k].target_start, intervals)
            t_prev = sorted_trans[k].target_start - timedelta(seconds=10)
            in_att_prev, _ = is_timestamp_in_attack(t_prev, intervals)
            if not in_att_prev and in_att_k:
                steps_to_onset = k - i + 1
                break

        labeled.append(
            LabeledTransition(
                sample=s,
                current_is_attack=1 if curr_is_att else 0,
                next_is_attack=1 if next_is_att else 0,
                current_stage=curr_stage,
                next_stage=next_stage,
                transition_type=ttype,
                steps_to_next_onset=steps_to_onset,
                lookahead_attack_h1=h1,
                lookahead_attack_h2=h2,
                lookahead_attack_h3=h3,
            )
        )

    return labeled
