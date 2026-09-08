"""Role-Specific Notification Engine with Deduplication and Suppression (SIH 26153)."""
from __future__ import annotations

from datetime import datetime
from typing import Mapping, Sequence

from core.contracts import (
    NotificationUrgency,
    PriorityAssessment,
    PriorityLevel,
    ResponseRecommendation,
    Role,
    RoleNotification,
    SecurityAssessment,
    TrustAssessment,
    new_id,
)
from core.response.roles import OperationalRole
from core.response.routing import RelevanceStatus, RoleRelevanceDecision
from security.contracts import StageHypothesis


class NotificationEngine:
    """
    Generates role-differentiated notifications and enforces suppression/update logic.
    """
    def __init__(self) -> None:
        # Cache of previous notifications per role: {role_value: last_notification_state}
        self._sent_cache: dict[str, dict[str, object]] = {}

    def generate_notifications(
        self,
        security_assessment: SecurityAssessment,
        priority_assessment: PriorityAssessment,
        stage_hypothesis: StageHypothesis,
        trust_assessment: TrustAssessment,
        recommendation: ResponseRecommendation,
        routing_decisions: Sequence[RoleRelevanceDecision],
        timestamp: datetime | None = None,
        force_update: bool = False,
    ) -> list[RoleNotification]:
        """
        Generate differentiated notifications for all relevant roles.
        Suppresses redundant notifications if telemetry/forecast state is unchanged.
        """
        now = timestamp or datetime.now()
        notifications: list[RoleNotification] = []
        stage = stage_hypothesis.candidate_stage
        prio = priority_assessment.priority_level
        conf = stage_hypothesis.confidence
        trust_val = trust_assessment.composite_trust

        # Map PriorityLevel to NotificationUrgency
        urgency_map = {
            PriorityLevel.CRITICAL: NotificationUrgency.ACTIVE,
            PriorityLevel.HIGH: NotificationUrgency.HIGH_PRIORITY,
            PriorityLevel.MEDIUM: NotificationUrgency.CONTEXT,
            PriorityLevel.LOW: NotificationUrgency.INFO,
            PriorityLevel.INFO: NotificationUrgency.NONE,
        }

        for dec in routing_decisions:
            op_role = dec.role
            contract_role = op_role.to_contract_role()
            
            # INVARIANT: If NOT_RELEVANT, strictly do NOT notify
            if dec.relevance == RelevanceStatus.NOT_RELEVANT:
                continue

            urgency = urgency_map.get(prio, NotificationUrgency.INFO)
            if dec.relevance == RelevanceStatus.CONDITIONAL and urgency == NotificationUrgency.HIGH_PRIORITY:
                urgency = NotificationUrgency.CONTEXT

            # 1. Generate Role-Differentiated Headlines and Content
            if op_role == OperationalRole.SOC_ANALYST:
                headline = f"[SOC Alert] {stage} Pattern Detected ({prio.value} Priority)"
                detail = (
                    f"Why: Active {stage} telemetry signature observed (Confidence={conf:.2f}, Trust={trust_val:.2f}). "
                    f"What changed: New telemetry indicators flagged across {len(dec.triggering_signatures)} signature dimensions. "
                    f"Forecast: Multi-step trajectory predicts continued pattern evolution. "
                    f"Action: Review triage queue and perform additional telemetry inspection. Human approval required: {recommendation.requires_human}."
                )
                affected = ("SOC Triage Queue", "Telemetry Stream")

            elif op_role == OperationalRole.NETWORK_DEFENDER:
                headline = f"[Network Defense] Boundary Telemetry Deviation — {stage}"
                detail = (
                    f"Why: Port/connection table deviation in stage '{stage}' requiring boundary awareness (Confidence={conf:.2f}, Trust={trust_val:.2f}). "
                    f"What changed: Triggering signatures: {', '.join(dec.triggering_signatures) or 'general deviation'}. "
                    f"Forecast: Trajectory forecast indicates potential boundary strain. "
                    f"Action: Consider reviewing ACLs / rate limiting. Recommended: {recommendation.reasoning}."
                )
                affected = ("Ingress / Egress Gateways", "TCP Session Table")

            elif op_role == OperationalRole.INCIDENT_COMMANDER:
                headline = f"[Incident Command] Emerging {stage} Incident Coordination ({prio.value})"
                detail = (
                    f"Why: Multi-step {stage} trajectory met Command elevation threshold. "
                    f"Confidence={conf:.2f}, Trust={trust_val:.2f} (Model Trust: {trust_assessment.trust_level.value}). "
                    f"Action: Overseeing human-gated response recommendation ({recommendation.strategy.value}). "
                    f"No destructive action will execute without explicit command approval."
                )
                affected = ("Incident Briefing Room", "Executive Response Log")

            elif op_role == OperationalRole.DATA_PROTECTION:
                headline = f"[Data Protection] Exfiltration / Bulk Transfer Advisory"
                detail = (
                    f"Why: Outbound volumetric byte surge detected matching exfiltration profile (Confidence={conf:.2f}, Trust={trust_val:.2f}). "
                    f"What changed: Byte transfer rate and mean packet size exceeded baseline threshold. "
                    f"Forecast: Volumetric staging trend continuation forecasted. "
                    f"Action: Initiate data flow compliance audit and review egress channel."
                )
                affected = ("Outbound Egress Channel", "Sensitive Asset Repositories")

            else:
                headline = f"[Security Advisory] {stage} Event"
                detail = f"Advisory for {op_role.value} regarding stage '{stage}' with priority {prio.value}."
                affected = ("Network Telemetry",)

            # 2. Suppression and Deduplication Check
            cache_key = op_role.value
            prev_entry = self._sent_cache.get(cache_key)
            current_fingerprint = {
                "stage": stage,
                "priority": prio.value,
                "confidence": round(conf, 2),
                "trust_level": trust_assessment.trust_level.value,
                "triggering": list(dec.triggering_signatures),
            }

            if not force_update and prev_entry is not None:
                # Check if materially unchanged
                if (
                    prev_entry["stage"] == current_fingerprint["stage"] and
                    prev_entry["priority"] == current_fingerprint["priority"] and
                    abs(float(prev_entry["confidence"]) - float(current_fingerprint["confidence"])) < 0.10 and
                    prev_entry["trust_level"] == current_fingerprint["trust_level"]
                ):
                    # Suppress duplicate notification
                    continue

            # Update cache and build notification
            self._sent_cache[cache_key] = current_fingerprint
            notifications.append(
                RoleNotification(
                    notification_id=new_id(f"notif-{op_role.value.lower()}"),
                    recommendation_id=recommendation.recommendation_id,
                    role=contract_role,
                    should_notify=(urgency != NotificationUrgency.NONE),
                    urgency=urgency,
                    headline=headline,
                    detail=detail,
                    affected_assets=affected,
                    confidence=conf,
                    timestamp=now,
                )
            )

        return notifications
