"""Human-Gated Response Recommendation Engine (SIH 26153).

Recommends reversible, non-destructive defensive actions requiring explicit human approval.
This module strictly NEVER executes actions.
"""
from __future__ import annotations

from typing import Sequence

from core.contracts import (
    ActionType,
    ActionUrgency,
    PriorityAssessment,
    PriorityLevel,
    RecommendedAction,
    ResponseRecommendation,
    SecurityAssessment,
    Strategy,
    TrustAssessment,
    TrustLevel,
    new_id,
)
from security.contracts import StageHypothesis


class ResponseRecommendationEngine:
    """
    Generates non-destructive, human-gated response recommendations based on
    PriorityAssessment, SecurityAssessment, StageHypothesis, and TrustAssessment.
    """
    def generate_recommendation(
        self,
        priority_assessment: PriorityAssessment,
        security_assessment: SecurityAssessment,
        stage_hypothesis: StageHypothesis,
        trust_assessment: TrustAssessment,
    ) -> ResponseRecommendation:
        """
        Produce a safe, reversible, human-gated recommendation.
        """
        stage = stage_hypothesis.candidate_stage
        prio = priority_assessment.priority_level
        trust = trust_assessment.trust_level
        actions: list[RecommendedAction] = []
        
        # 1. Determine Strategy
        if stage == "Unknown" or prio == PriorityLevel.INFO:
            strategy = Strategy.MONITOR
            actions.append(
                RecommendedAction(
                    action_type=ActionType.INCREASE_MONITORING,
                    target="Baseline telemetry stream",
                    reversible=True,
                    urgency=ActionUrgency.WHEN_CONVENIENT,
                )
            )
            reasoning = "Traffic consistent with baseline or ambiguous. Recommended action is continued monitoring without intervention."

        elif trust in (TrustLevel.LOW, TrustLevel.INSUFFICIENT):
            # Low trust forces observation / inspection strategy
            strategy = Strategy.MONITOR
            actions.append(
                RecommendedAction(
                    action_type=ActionType.ADDITIONAL_INSPECTION,
                    target="Affected network telemetry buffer",
                    reversible=True,
                    urgency=ActionUrgency.SOON,
                )
            )
            reasoning = f"Low forecast trust ({trust.value}) indicates high model uncertainty. Recommended action is additional telemetry collection before any containment."

        elif prio in (PriorityLevel.CRITICAL, PriorityLevel.HIGH):
            strategy = Strategy.ACT
            if stage == "Impact / Denial of Service":
                actions.append(
                    RecommendedAction(
                        action_type=ActionType.RATE_LIMIT,
                        target="Inbound connection pool / ingress gateway",
                        reversible=True,
                        urgency=ActionUrgency.IMMEDIATE,
                    )
                )
                actions.append(
                    RecommendedAction(
                        action_type=ActionType.ADDITIONAL_INSPECTION,
                        target="TCP SYN/RST backlog queues",
                        reversible=True,
                        urgency=ActionUrgency.IMMEDIATE,
                    )
                )
                reasoning = "Elevated connection flooding with high confidence. Recommended human-approved reversible rate limiting and queue inspection."
            elif stage == "Collection / Exfiltration":
                actions.append(
                    RecommendedAction(
                        action_type=ActionType.RESTRICT_COMMS,
                        target="Outbound bulk egress channel",
                        reversible=True,
                        urgency=ActionUrgency.IMMEDIATE,
                    )
                )
                actions.append(
                    RecommendedAction(
                        action_type=ActionType.ADDITIONAL_INSPECTION,
                        target="Outbound flow payload staging logs",
                        reversible=True,
                        urgency=ActionUrgency.SOON,
                    )
                )
                reasoning = "Sustained high-volume outbound surge detected. Recommended human-approved egress rate restriction and log review."
            else:  # Reconnaissance / Initial Access
                actions.append(
                    RecommendedAction(
                        action_type=ActionType.RESTRICT_COMMS,
                        target="Exposed service port boundaries",
                        reversible=True,
                        urgency=ActionUrgency.SOON,
                    )
                )
                actions.append(
                    RecommendedAction(
                        action_type=ActionType.ADDITIONAL_INSPECTION,
                        target="Service discovery ingress records",
                        reversible=True,
                        urgency=ActionUrgency.SOON,
                    )
                )
                reasoning = f"Active {stage} pattern with high priority. Recommended human-approved boundary review and service ACL inspection."

        elif prio == PriorityLevel.MEDIUM:
            strategy = Strategy.PREPARE
            actions.append(
                RecommendedAction(
                    action_type=ActionType.ADDITIONAL_INSPECTION,
                    target="Target service endpoints",
                    reversible=True,
                    urgency=ActionUrgency.SOON,
                )
            )
            actions.append(
                RecommendedAction(
                    action_type=ActionType.INCREASE_MONITORING,
                    target="Specific port/flow sequence",
                    reversible=True,
                    urgency=ActionUrgency.SOON,
                )
            )
            reasoning = f"Moderate priority event in stage '{stage}'. Recommended inspection and elevated telemetry polling."

        else:  # LOW
            strategy = Strategy.MONITOR
            actions.append(
                RecommendedAction(
                    action_type=ActionType.INCREASE_MONITORING,
                    target="Flow observation window",
                    reversible=True,
                    urgency=ActionUrgency.WHEN_CONVENIENT,
                )
            )
            reasoning = f"Low priority event in stage '{stage}'. Routine monitoring recommended."

        # Safety Invariants:
        # 1. is_reversible MUST be True
        # 2. requires_human MUST be True
        return ResponseRecommendation(
            recommendation_id=new_id("rec"),
            priority_assessment_id=priority_assessment.assessment_id,
            trust_level=trust,
            strategy=strategy,
            actions=tuple(actions),
            is_reversible=True,
            requires_human=True,
            reasoning=reasoning,
        )
