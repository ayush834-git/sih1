"""Confidence -> Authority Policy Engine (SIH 26153 Task 20).

Translates multi-signal evidence quality (trust, uncertainty, topology availability,
and structural blast radius) into conservative, deterministic operational authority decisions.

CORE PRINCIPLE:
HIGH RISK != HIGH AUTHORITY
Authority is bounded by evidence quality and conservative policy, not risk score alone.
Destructive actions are NEVER autonomous.
Missing or invalid inputs fail closed.
"""
from __future__ import annotations

from core.authority.models import (
    ActionClass,
    AuthorityDecision,
    AuthorityLevel,
    AuthorityPolicyInput,
)
from core.contracts import TrustLevel, new_id
from core.topology.models import TopologyAvailability

POLICY_VERSION = "authority-v1"


class AuthorityPolicyEngine:
    """
    Deterministic rule-based policy engine mapping evidence quality to justified operational authority.
    """

    def __init__(self, policy_version: str = POLICY_VERSION) -> None:
        self.policy_version = policy_version

    def evaluate(self, policy_input: AuthorityPolicyInput) -> AuthorityDecision:
        """
        Evaluate an AuthorityPolicyInput and return an immutable AuthorityDecision.
        """
        decision_id = new_id("auth-dec")

        # 1. Fail-Closed on Invalid or Missing Inputs (Invariant 7)
        if not isinstance(policy_input, AuthorityPolicyInput) or not policy_input.is_valid():
            return AuthorityDecision(
                decision_id=decision_id,
                authority_level=AuthorityLevel.OBSERVE,
                permitted_action_classes=(ActionClass.OBSERVE_ONLY,),
                blocked_action_classes=(
                    ActionClass.ALERT_OPERATOR,
                    ActionClass.GENERATE_RECOMMENDATION,
                    ActionClass.PREPARE_REVERSIBLE_ACTION,
                    ActionClass.EXECUTE_REVERSIBLE_ACTION,
                    ActionClass.EXECUTE_DESTRUCTIVE_ACTION,
                ),
                human_approval_required=True,
                policy_version=self.policy_version,
                reason_codes=("FAIL_CLOSED_INVALID_OR_MISSING_INPUT",),
                explanation=(
                    "Policy failed closed due to missing, NaN, or out-of-bounds evidence inputs "
                    "(e.g. missing explicit uncertainty metric). All operational action classes are blocked."
                ),
            )

        permitted: list[ActionClass] = [ActionClass.OBSERVE_ONLY]
        blocked: list[ActionClass] = []
        reason_codes: list[str] = []

        # 2. Invariant 6: Destructive actions are NEVER autonomous
        blocked.append(ActionClass.EXECUTE_DESTRUCTIVE_ACTION)
        reason_codes.append("DESTRUCTIVE_ACTIONS_PERMANENTLY_BLOCKED")

        # 3. Alert Operator Gate (ALERT_OPERATOR)
        # Operators are alerted when there is non-trivial risk, affected nodes, or stage evidence
        if (
            policy_input.risk_score >= 0.15
            or policy_input.affected_node_count > 0
            or policy_input.stage_confidence >= 0.30
        ):
            permitted.append(ActionClass.ALERT_OPERATOR)
            reason_codes.append("SIGNIFICANT_SIGNAL_PERMITS_ALERT")
        else:
            blocked.append(ActionClass.ALERT_OPERATOR)
            reason_codes.append("LOW_SIGNAL_OMITS_ALERT")

        eff_unc = policy_input.effective_uncertainty

        # 4. Recommendation Formulation Gate (GENERATE_RECOMMENDATION)
        # Requires at least moderate trust and bounded uncertainty
        trust_ok_for_rec = (
            policy_input.composite_trust >= 0.45
            and policy_input.trust_level != TrustLevel.INSUFFICIENT
            and (eff_unc is not None and eff_unc <= 0.50)
        )
        if trust_ok_for_rec:
            permitted.append(ActionClass.GENERATE_RECOMMENDATION)
            reason_codes.append("ADEQUATE_TRUST_PERMITS_RECOMMENDATION")
        else:
            blocked.append(ActionClass.GENERATE_RECOMMENDATION)
            reason_codes.append("LOW_TRUST_BLOCKS_RECOMMENDATION")

        # 5. Prepare Reversible Action Gate (PREPARE_REVERSIBLE_ACTION)
        # Requires valid recommendation, higher trust threshold, and non-unavailable topology
        can_prepare = (
            ActionClass.GENERATE_RECOMMENDATION in permitted
            and policy_input.composite_trust >= 0.55
            and (eff_unc is not None and eff_unc <= 0.40)
            and policy_input.topology_availability != TopologyAvailability.UNAVAILABLE
        )
        if can_prepare:
            permitted.append(ActionClass.PREPARE_REVERSIBLE_ACTION)
            reason_codes.append("REVERSIBLE_PREPARATION_AUTHORIZED")
        else:
            blocked.append(ActionClass.PREPARE_REVERSIBLE_ACTION)
            if policy_input.topology_availability == TopologyAvailability.UNAVAILABLE:
                reason_codes.append("UNAVAILABLE_TOPOLOGY_BLOCKS_PREPARATION")
            else:
                reason_codes.append("INSUFFICIENT_EVIDENCE_FOR_PREPARATION")

        # 6. Execute Reversible Action Gate (EXECUTE_REVERSIBLE_ACTION)
        # Conservative Invariant 1 & 2: High authority strictly requires high trust and low uncertainty.
        # Invariant 3: UNAVAILABLE topology strictly blocks execution.
        # Invariant 4: PARTIAL topology mandates human approval.
        high_evidence_quality = (
            policy_input.composite_trust >= 0.70
            and (eff_unc is not None and eff_unc <= 0.25)
            and policy_input.trust_level == TrustLevel.HIGH
            and policy_input.stage_confidence >= 0.50
        )

        if policy_input.topology_availability == TopologyAvailability.UNAVAILABLE:
            blocked.append(ActionClass.EXECUTE_REVERSIBLE_ACTION)
            reason_codes.append("UNAVAILABLE_TOPOLOGY_BLOCKS_EXECUTION")
        elif not high_evidence_quality:
            blocked.append(ActionClass.EXECUTE_REVERSIBLE_ACTION)
            reason_codes.append("INSUFFICIENT_CONFIDENCE_FOR_EXECUTION")
        else:
            # High evidence quality met with KNOWN or PARTIAL topology
            permitted.append(ActionClass.EXECUTE_REVERSIBLE_ACTION)
            if policy_input.topology_availability == TopologyAvailability.PARTIAL:
                reason_codes.append("PARTIAL_TOPOLOGY_REQUIRES_HUMAN_APPROVAL")
            else:
                reason_codes.append("STRONG_EVIDENCE_PERMITS_HUMAN_GATED_EXECUTION")

        # 7. Human Approval Invariant
        # Human approval is mandatory for any consequential containment action,
        # or whenever topology is partial or structural blast radius is high.
        human_approval_required = (
            ActionClass.EXECUTE_REVERSIBLE_ACTION in permitted
            or ActionClass.PREPARE_REVERSIBLE_ACTION in permitted
            or policy_input.topology_availability == TopologyAvailability.PARTIAL
            or policy_input.risk_score >= 0.60
            or policy_input.critical_affected_node_count > 0
        )

        # 8. Blast Radius Urgency Interaction (Invariant 5)
        # Blast radius increases review urgency, but does NOT grant higher authority
        if policy_input.weighted_structural_impact >= 0.70 or policy_input.critical_affected_node_count > 0:
            reason_codes.append("HIGH_STRUCTURAL_BLAST_RADIUS_URGENCY")

        # 9. Reconsideration Tracking
        if policy_input.is_reconsideration:
            reason_codes.append("RECONSIDERED_EVIDENCE_EVALUATED")

        # 10. Determine Final Authority Level
        req = policy_input.requested_action_class
        if req is not None:
            if req in blocked:
                authority_level = AuthorityLevel.BLOCKED
            elif req == ActionClass.EXECUTE_REVERSIBLE_ACTION:
                authority_level = AuthorityLevel.HUMAN_APPROVAL_REQUIRED
            elif req == ActionClass.PREPARE_REVERSIBLE_ACTION:
                authority_level = AuthorityLevel.HUMAN_APPROVAL_REQUIRED if human_approval_required else AuthorityLevel.RECOMMEND
            elif req == ActionClass.GENERATE_RECOMMENDATION:
                authority_level = AuthorityLevel.RECOMMEND
            elif req == ActionClass.ALERT_OPERATOR:
                authority_level = AuthorityLevel.ALERT
            else:
                authority_level = AuthorityLevel.OBSERVE
        else:
            # Maximum justified authority supported by current evidence
            if ActionClass.EXECUTE_REVERSIBLE_ACTION in permitted:
                authority_level = AuthorityLevel.HUMAN_APPROVAL_REQUIRED
            elif ActionClass.PREPARE_REVERSIBLE_ACTION in permitted:
                authority_level = AuthorityLevel.HUMAN_APPROVAL_REQUIRED if human_approval_required else AuthorityLevel.RECOMMEND
            elif ActionClass.GENERATE_RECOMMENDATION in permitted:
                authority_level = AuthorityLevel.RECOMMEND
            elif ActionClass.ALERT_OPERATOR in permitted:
                authority_level = AuthorityLevel.ALERT
            else:
                authority_level = AuthorityLevel.OBSERVE

        explanation = (
            f"Authority decision '{authority_level.value}' under policy {self.policy_version}: "
            f"Risk={policy_input.risk_score:.2f}, Trust={policy_input.composite_trust:.2f} ({policy_input.trust_level.value}), "
            f"Uncertainty={eff_unc if eff_unc is not None else 'N/A'}, "
            f"Topology={policy_input.topology_availability.value}. "
            f"Permitted actions: {[a.value for a in permitted]}; Blocked: {[b.value for b in blocked]}. "
            f"Human approval required: {human_approval_required}. "
            "NOTE: High risk alone does NOT grant execution authority; all containment actions remain human-gated."
        )

        return AuthorityDecision(
            decision_id=decision_id,
            authority_level=authority_level,
            permitted_action_classes=tuple(permitted),
            blocked_action_classes=tuple(blocked),
            human_approval_required=human_approval_required,
            policy_version=self.policy_version,
            reason_codes=tuple(reason_codes),
            explanation=explanation,
        )
