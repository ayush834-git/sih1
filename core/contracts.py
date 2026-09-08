"""Frozen SIH 26153 boundary contracts. No production analytics live here."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from hashlib import sha256
from math import isfinite
from typing import Mapping, Sequence
from uuid import uuid4


STATE_FEATURES = (
    "flow_count", "byte_rate", "packet_rate", "mean_flow_duration",
    "src_ip_diversity", "dst_ip_diversity", "src_port_diversity",
    "dst_port_diversity", "fan_out", "internal_ratio", "east_west_count",
    "syn_count", "ack_count", "rst_count", "syn_ratio", "rst_ratio",
    "iat_mean", "iat_std", "pkt_size_mean", "pkt_size_std", "byte_variance",
)
STATE_SCHEMA_HASH = sha256("|".join(STATE_FEATURES).encode()).hexdigest()


class Source(str, Enum): CSV = "csv"; PCAP = "pcap"; MERGED = "merged"
class FeatureAvailability(str, Enum): AVAILABLE = "AVAILABLE"; UNAVAILABLE = "UNAVAILABLE"; INVALID = "INVALID"
class TrustLevel(str, Enum): HIGH = "HIGH"; MEDIUM = "MEDIUM"; LOW = "LOW"; INSUFFICIENT = "INSUFFICIENT"
class Direction(str, Enum): INCREASES_TRUST = "INCREASES_TRUST"; DECREASES_TRUST = "DECREASES_TRUST"
class EvidenceDirection(str, Enum): UP = "UP"; DOWN = "DOWN"; STABLE = "STABLE"
class PriorityLevel(str, Enum): CRITICAL = "CRITICAL"; HIGH = "HIGH"; MEDIUM = "MEDIUM"; LOW = "LOW"; INFO = "INFO"
class Strategy(str, Enum): ACT = "ACT"; PREPARE = "PREPARE"; MONITOR = "MONITOR"; ESCALATE = "ESCALATE"
class ActionType(str, Enum): RATE_LIMIT = "RATE_LIMIT"; QUARANTINE = "QUARANTINE"; RESTRICT_COMMS = "RESTRICT_COMMS"; BLOCK = "BLOCK"; INCREASE_MONITORING = "INCREASE_MONITORING"; ADDITIONAL_INSPECTION = "ADDITIONAL_INSPECTION"; NO_ACTION = "NO_ACTION"
class ActionUrgency(str, Enum): IMMEDIATE = "IMMEDIATE"; SOON = "SOON"; WHEN_CONVENIENT = "WHEN_CONVENIENT"
class Role(str, Enum): NETWORK_SECURITY = "NETWORK_SECURITY"; INCIDENT_RESPONSE = "INCIDENT_RESPONSE"; THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"; CLOUD_SYSTEM_ADMIN = "CLOUD_SYSTEM_ADMIN"
class NotificationUrgency(str, Enum): ACTIVE = "ACTIVE"; HIGH_PRIORITY = "HIGH_PRIORITY"; CONTEXT = "CONTEXT"; INFO = "INFO"; NONE = "NONE"


def _score(value: float, name: str) -> None:
    if not isfinite(value) or not 0 <= value <= 1: raise ValueError(f"{name} must be a finite score in [0, 1]")
def _nonnegative(value: float, name: str) -> None:
    if value < 0: raise ValueError(f"{name} must be non-negative")


@dataclass(frozen=True)
class NetworkState:
    window_id: str; timestamp_start: datetime; timestamp_end: datetime; window_duration_s: float
    flow_count: int; byte_rate: float; packet_rate: float; mean_flow_duration: float
    src_ip_diversity: int | None; dst_ip_diversity: int | None; src_port_diversity: int | None; dst_port_diversity: int; fan_out: float | None; internal_ratio: float | None; east_west_count: int | None
    syn_count: int; ack_count: int; rst_count: int; syn_ratio: float; rst_ratio: float
    iat_mean: float; iat_std: float; iat_skew: float | None; pkt_size_mean: float; pkt_size_std: float; byte_variance: float
    ttl_mean: float | None; ttl_variance: float | None; tcp_window_mean: float | None; fragment_count: int | None; retransmit_count: int | None; payload_size_mean: float | None
    source: Source; data_quality: float; is_empty: bool; gap_before: bool; gap_after: bool; session_id: str; provenance_hash: str
    feature_availability: Mapping[str, FeatureAvailability] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.window_id or not self.session_id: raise ValueError("window_id and session_id are required")
        if abs((self.timestamp_end - self.timestamp_start).total_seconds() - self.window_duration_s) > 0.01: raise ValueError("timestamp duration must match window_duration_s")
        _nonnegative(self.flow_count, "flow_count"); _score(self.data_quality, "data_quality")
        for name in ("src_ip_diversity", "dst_ip_diversity", "src_port_diversity", "dst_port_diversity", "east_west_count", "syn_count", "ack_count", "rst_count"):
            value = getattr(self, name)
            if value is not None: _nonnegative(value, name)
        for name in ("internal_ratio", "syn_ratio", "rst_ratio"):
            value = getattr(self, name)
            if value is not None: _score(value, name)
        if self.is_empty != (self.flow_count == 0): raise ValueError("is_empty must exactly match flow_count == 0")
        if self.data_quality == 0.0 and not self.is_empty: raise ValueError("data_quality 0 requires empty window")
        if len(self.provenance_hash) != 64: raise ValueError("provenance_hash must be SHA-256")

    def feature_values(self) -> dict[str, float]:
        """Only measured, valid predictive features; unavailable values never become zero."""
        return {name: float(getattr(self, name)) for name in STATE_FEATURES if getattr(self, name) is not None and self.feature_availability.get(name, FeatureAvailability.AVAILABLE) == FeatureAvailability.AVAILABLE}
    @property
    def transitions_allowed(self) -> bool: return not (self.gap_before or self.gap_after)


@dataclass(frozen=True)
class Forecast:
    forecast_id: str; source_state_id: str; target_timestamp: datetime; horizon_steps: int; delta_predicted: Mapping[str, float]; state_predicted: Mapping[str, float]
    model_id: str; model_version: str; feature_schema_hash: str; created_at: datetime; failure_reason: str | None = None
    def __post_init__(self) -> None:
        if self.horizon_steps < 1: raise ValueError("horizon_steps must be >= 1")
        if not self.failure_reason and (not self.delta_predicted or set(self.delta_predicted) != set(self.state_predicted)): raise ValueError("successful forecast needs matching non-empty state and delta features")
        if self.failure_reason and (self.delta_predicted or self.state_predicted): raise ValueError("failed forecast must have empty predictions")
    def validate_against(self, source: NetworkState) -> None:
        if source.window_id != self.source_state_id or self.feature_schema_hash != STATE_SCHEMA_HASH: raise ValueError("forecast source or schema mismatch")
        for name, delta in self.delta_predicted.items():
            if abs(self.state_predicted[name] - (source.feature_values()[name] + delta)) > 1e-9: raise ValueError("state prediction must equal state plus delta")


@dataclass(frozen=True)
class TrajectoryStep:
    step_index: int; forecast: Forecast; observed_state: NetworkState | None = None; step_error: float | None = None
    def __post_init__(self) -> None:
        if self.step_index < 0: raise ValueError("step_index must be non-negative")
        if (self.observed_state is None) != (self.step_error is None): raise ValueError("observed state and step error must appear together")

@dataclass(frozen=True)
class Trajectory:
    trajectory_id: str; parent_state_id: str; steps: Sequence[TrajectoryStep]; weight: float; cumulative_error: float | None; is_active: bool; pruned_reason: str | None; created_at: datetime; last_updated: datetime
    def __post_init__(self) -> None:
        _score(self.weight, "weight")
        if self.last_updated < self.created_at: raise ValueError("last_updated precedes created_at")
        if not self.is_active and not self.pruned_reason: raise ValueError("pruned trajectory needs a reason")
        if any(s.step_index != i for i, s in enumerate(self.steps)): raise ValueError("trajectory steps must be ordered from zero")


@dataclass(frozen=True)
class TrustFactor: name: str; value: float; direction: Direction
@dataclass(frozen=True)
class TrustAssessment:
    assessment_id: str; forecast_id: str; forecast_confidence: float; model_disagreement: float; distribution_shift_score: float; novelty_score: float; historical_error: float; data_quality: float; composite_trust: float; trust_level: TrustLevel; contributing_factors: Sequence[TrustFactor]
    def __post_init__(self) -> None:
        for name in ("forecast_confidence", "model_disagreement", "distribution_shift_score", "novelty_score", "data_quality", "composite_trust"): _score(getattr(self, name), name)
        _nonnegative(self.historical_error, "historical_error")
        if not self.contributing_factors: raise ValueError("contributing_factors cannot be empty")


@dataclass(frozen=True)
class StageCandidate:
    stage_name: str; attack_technique_id: str | None; evidence_score: float; is_primary: bool
    def __post_init__(self) -> None: _score(self.evidence_score, "evidence_score")
@dataclass(frozen=True)
class EvidenceItem:
    feature_name: str; feature_value: float; direction: EvidenceDirection; contribution: float
@dataclass(frozen=True)
class SecurityAssessment:
    assessment_id: str; trajectory_id: str; trust_assessment_id: str; behavioural_signature: Mapping[str, float]; candidate_stages: Sequence[StageCandidate]; primary_stage: StageCandidate; evidence_summary: Sequence[EvidenceItem]; is_novel: bool
    def __post_init__(self) -> None:
        if not self.candidate_stages or self.primary_stage != self.candidate_stages[0] or not self.primary_stage.is_primary: raise ValueError("primary stage must be first, present, and primary")
        if not any(s.stage_name == "Unknown" for s in self.candidate_stages): raise ValueError("Unknown must remain a candidate")


@dataclass(frozen=True)
class PriorityAssessment:
    assessment_id: str; security_assessment_id: str; likelihood: float; consequence: float; asset_criticality: float; attack_path_leverage: float; proximity: float; actionability: float; composite_priority: float; priority_level: PriorityLevel; reasoning: str
    def __post_init__(self) -> None:
        for name in ("likelihood", "consequence", "asset_criticality", "attack_path_leverage", "proximity", "actionability", "composite_priority"): _score(getattr(self, name), name)
        if not self.reasoning: raise ValueError("priority reasoning is required")


@dataclass(frozen=True)
class RecommendedAction:
    action_type: ActionType; target: str; reversible: bool; urgency: ActionUrgency
    def __post_init__(self) -> None:
        if not self.target or not self.reversible: raise ValueError("actions must name a target and be reversible")
@dataclass(frozen=True)
class ResponseRecommendation:
    recommendation_id: str; priority_assessment_id: str; trust_level: TrustLevel; strategy: Strategy; actions: Sequence[RecommendedAction]; is_reversible: bool; requires_human: bool; reasoning: str
    def __post_init__(self) -> None:
        if not self.actions or not self.is_reversible or not all(a.reversible for a in self.actions): raise ValueError("only reversible recommendations are allowed")
        if self.trust_level in (TrustLevel.LOW, TrustLevel.INSUFFICIENT) and not self.requires_human: raise ValueError("low trust requires a human")
        if self.strategy == Strategy.ESCALATE and not self.requires_human: raise ValueError("escalation requires a human")


@dataclass(frozen=True)
class RoleNotification:
    notification_id: str; recommendation_id: str; role: Role; should_notify: bool; urgency: NotificationUrgency; headline: str; detail: str; affected_assets: Sequence[str]; confidence: float; timestamp: datetime
    def __post_init__(self) -> None:
        _score(self.confidence, "confidence")
        if self.should_notify != (self.urgency != NotificationUrgency.NONE): raise ValueError("urgency NONE must exactly match non-notification")


def new_id(prefix: str) -> str: return f"{prefix}-{uuid4()}"
