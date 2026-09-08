"""Deterministic Role-Relevance Routing Engine (SIH 26153)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence

from core.contracts import PriorityAssessment, PriorityLevel, SecurityAssessment, TrustAssessment
from core.response.roles import DEFAULT_ROLE_PROFILES, OperationalRole, RoleProfile
from security.contracts import EvidenceStrength, SignatureType, StageHypothesis


class RelevanceStatus(str, Enum):
    RELEVANT = "RELEVANT"
    NOT_RELEVANT = "NOT_RELEVANT"
    CONDITIONAL = "CONDITIONAL"


@dataclass(frozen=True)
class RoleRelevanceDecision:
    """Deterministic routing decision for a specific operational role."""
    role: OperationalRole
    relevance: RelevanceStatus
    reasons: tuple[str, ...]
    triggering_signatures: tuple[str, ...]
    priority_level: PriorityLevel
    attention_window_s: int

    def to_dict(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "relevance": self.relevance.value,
            "reasons": list(self.reasons),
            "triggering_signatures": list(self.triggering_signatures),
            "priority_level": self.priority_level.value,
            "attention_window_s": self.attention_window_s,
        }


class RoleRelevanceEngine:
    """
    Evaluates SecurityAssessment, PriorityAssessment, and Role Profiles to determine
    which roles should receive notifications.
    """
    def __init__(self, profiles: Mapping[OperationalRole, RoleProfile] | None = None) -> None:
        self.profiles = dict(profiles or DEFAULT_ROLE_PROFILES)

    def route_event(
        self,
        security_assessment: SecurityAssessment,
        priority_assessment: PriorityAssessment,
        stage_hypothesis: StageHypothesis,
        trust_assessment: TrustAssessment,
    ) -> list[RoleRelevanceDecision]:
        """
        Evaluate relevance for all configured operational roles.
        """
        decisions: list[RoleRelevanceDecision] = []
        stage = stage_hypothesis.candidate_stage
        prio = priority_assessment.priority_level
        active_sigs = [
            SignatureType(k) for k, v in security_assessment.behavioural_signature.items() if v >= 0.40
        ]
        
        # Priority ranking helper for comparisons
        prio_ranks = {
            PriorityLevel.INFO: 0,
            PriorityLevel.LOW: 1,
            PriorityLevel.MEDIUM: 2,
            PriorityLevel.HIGH: 3,
            PriorityLevel.CRITICAL: 4,
        }
        event_prio_rank = prio_ranks.get(prio, 0)

        for op_role, profile in self.profiles.items():
            min_rank = prio_ranks.get(profile.min_priority, 0)
            stage_match = stage in profile.relevant_stages
            sig_match = any(sig in profile.relevant_signatures for sig in active_sigs)
            
            reasons = []
            triggering = [sig.value for sig in active_sigs if sig in profile.relevant_signatures]
            
            # 1. Benign / Unknown handling
            if stage == "Unknown":
                decisions.append(
                    RoleRelevanceDecision(
                        role=op_role,
                        relevance=RelevanceStatus.NOT_RELEVANT,
                        reasons=("Event classified as baseline / Unknown; no role action required.",),
                        triggering_signatures=(),
                        priority_level=prio,
                        attention_window_s=0,
                    )
                )
                continue

            # 2. Endpoint Analyst Guard (Topology unavailable in CSV telemetry)
            if op_role == OperationalRole.ENDPOINT_ANALYST:
                decisions.append(
                    RoleRelevanceDecision(
                        role=op_role,
                        relevance=RelevanceStatus.NOT_RELEVANT,
                        reasons=("Host/EDR telemetry UNAVAILABLE in current CSV flow source; event not routed to Endpoint Analyst.",),
                        triggering_signatures=(),
                        priority_level=prio,
                        attention_window_s=0,
                    )
                )
                continue

            # 3. Incident Commander Threshold
            if op_role == OperationalRole.INCIDENT_COMMANDER:
                if event_prio_rank >= min_rank and (stage in ("Impact / Denial of Service", "Collection / Exfiltration")):
                    relevance = RelevanceStatus.RELEVANT
                    reasons.append(f"High-consequence stage '{stage}' requires incident command coordination.")
                    window = 60
                elif event_prio_rank >= min_rank:
                    relevance = RelevanceStatus.CONDITIONAL
                    reasons.append(f"Elevated priority ({prio.value}) on '{stage}' stage under observation.")
                    window = 120
                else:
                    relevance = RelevanceStatus.NOT_RELEVANT
                    reasons.append(f"Priority ({prio.value}) below Commander threshold ({profile.min_priority.value}).")
                    window = 0
                    
                decisions.append(
                    RoleRelevanceDecision(
                        role=op_role,
                        relevance=relevance,
                        reasons=tuple(reasons),
                        triggering_signatures=tuple(triggering),
                        priority_level=prio,
                        attention_window_s=window,
                    )
                )
                continue

            # 4. Data Protection Officer Threshold
            if op_role == OperationalRole.DATA_PROTECTION:
                if stage == "Collection / Exfiltration" or SignatureType.EXFILTRATION_OUTBOUND_SURGE in active_sigs:
                    relevance = RelevanceStatus.RELEVANT
                    reasons.append("Outbound volumetric transfer matches data loss prevention mandate.")
                    window = 120
                else:
                    relevance = RelevanceStatus.NOT_RELEVANT
                    reasons.append("No exfiltration or sensitive data staging activity detected.")
                    window = 0
                    
                decisions.append(
                    RoleRelevanceDecision(
                        role=op_role,
                        relevance=relevance,
                        reasons=tuple(reasons),
                        triggering_signatures=tuple(triggering),
                        priority_level=prio,
                        attention_window_s=window,
                    )
                )
                continue

            # 5. General Role Evaluation (SOC Analyst & Network Defender)
            if stage_match and sig_match and event_prio_rank >= min_rank:
                relevance = RelevanceStatus.RELEVANT
                reasons.append(f"Active signature matches role domain '{profile.display_name}'.")
                window = 30 if event_prio_rank >= 3 else 90
            elif stage_match or sig_match:
                relevance = RelevanceStatus.CONDITIONAL
                reasons.append(f"Partial domain match on '{stage}' with priority {prio.value}.")
                window = 180
            else:
                relevance = RelevanceStatus.NOT_RELEVANT
                reasons.append("No active signature or stage overlap with role responsibilities.")
                window = 0

            decisions.append(
                RoleRelevanceDecision(
                    role=op_role,
                    relevance=relevance,
                    reasons=tuple(reasons),
                    triggering_signatures=tuple(triggering),
                    priority_level=prio,
                    attention_window_s=window,
                )
            )

        return decisions
