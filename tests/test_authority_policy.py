"""Comprehensive Test Suite for Confidence -> Authority Policy (SIH 26153 Task 20).

Validates:
1. Core Principle: HIGH RISK != HIGH AUTHORITY.
2. Conservative Invariants (low trust constrains authority, high uncertainty constrains authority,
   unavailable topology blocks execution/preparation, partial topology mandates human approval,
   destructive actions permanently blocked, blast radius increases urgency without expanding authority).
3. Fail-closed semantics on missing, NaN, or out-of-bounds inputs.
4. Reuse of existing uncertainty contract (direct or horizon-specific; never synthetic 1.0 - trust).
5. 3 Monotonicity guarantees (trust, uncertainty, topology).
6. Deterministic SHA-256 provenance hashes and reason codes.
7. End-to-end integration into DemoEvent and LiveDemoEngine.
"""
from __future__ import annotations

import unittest
from datetime import datetime

from core.authority.models import (
    ActionClass,
    AuthorityDecision,
    AuthorityLevel,
    AuthorityPolicyInput,
)
from core.authority.policy import AuthorityPolicyEngine, POLICY_VERSION
from core.blastradius.models import BlastRadiusStatus
from core.contracts import FeatureAvailability, NetworkState, TrustLevel
from core.topology.models import TopologyAvailability
from eval.metrics_v2 import RobustScaleStatistics
from scenarios.demo.engine import DemoEvent, LiveDemoEngine


class TestAuthorityPolicy(unittest.TestCase):
    """Unit and integration tests for AuthorityPolicyEngine and data contracts."""

    def setUp(self) -> None:
        self.engine = AuthorityPolicyEngine()

    def _base_valid_input(
        self,
        risk_score: float = 0.50,
        composite_trust: float = 0.80,
        uncertainty: float | None = 0.15,
        trust_level: TrustLevel = TrustLevel.HIGH,
        stage_confidence: float = 0.70,
        topology_availability: TopologyAvailability = TopologyAvailability.KNOWN,
        affected_node_count: int = 2,
        requested_action_class: ActionClass | None = None,
        is_reconsideration: bool = False,
    ) -> AuthorityPolicyInput:
        return AuthorityPolicyInput(
            risk_score=risk_score,
            forecast_trust=composite_trust,
            composite_trust=composite_trust,
            uncertainty=uncertainty,
            trust_level=trust_level,
            stage_confidence=stage_confidence,
            topology_availability=topology_availability,
            blast_radius_status=BlastRadiusStatus.COMPLETE,
            blast_radius_coverage=1.0,
            affected_node_count=affected_node_count,
            critical_affected_node_count=0,
            weighted_structural_impact=0.30,
            requested_action_class=requested_action_class,
            is_reconsideration=is_reconsideration,
        )

    # 1. Enum Definitions
    def test_authority_level_enum_and_semantics(self) -> None:
        expected = {"OBSERVE", "ALERT", "RECOMMEND", "HUMAN_APPROVAL_REQUIRED", "BLOCKED"}
        self.assertEqual({lvl.value for lvl in AuthorityLevel}, expected)

    def test_action_class_enum_and_semantics(self) -> None:
        expected = {
            "OBSERVE_ONLY",
            "ALERT_OPERATOR",
            "GENERATE_RECOMMENDATION",
            "PREPARE_REVERSIBLE_ACTION",
            "EXECUTE_REVERSIBLE_ACTION",
            "EXECUTE_DESTRUCTIVE_ACTION",
        }
        self.assertEqual({ac.value for ac in ActionClass}, expected)

    # 2. High Evidence -> Reversible Human-Gated Execution
    def test_high_evidence_permits_reversible_human_gated(self) -> None:
        inp = self._base_valid_input(
            risk_score=0.65,
            composite_trust=0.85,
            uncertainty=0.15,
            trust_level=TrustLevel.HIGH,
            stage_confidence=0.75,
            topology_availability=TopologyAvailability.KNOWN,
        )
        dec = self.engine.evaluate(inp)
        self.assertEqual(dec.authority_level, AuthorityLevel.HUMAN_APPROVAL_REQUIRED)
        self.assertIn(ActionClass.EXECUTE_REVERSIBLE_ACTION, dec.permitted_action_classes)
        self.assertIn(ActionClass.PREPARE_REVERSIBLE_ACTION, dec.permitted_action_classes)
        self.assertIn(ActionClass.GENERATE_RECOMMENDATION, dec.permitted_action_classes)
        self.assertIn(ActionClass.ALERT_OPERATOR, dec.permitted_action_classes)
        self.assertTrue(dec.human_approval_required)
        self.assertIn("STRONG_EVIDENCE_PERMITS_HUMAN_GATED_EXECUTION", dec.reason_codes)

    # 3. Low Trust Constrains Authority
    def test_low_trust_constrains_authority(self) -> None:
        inp = self._base_valid_input(
            risk_score=0.85,  # High risk!
            composite_trust=0.25,  # Low trust!
            uncertainty=0.20,
            trust_level=TrustLevel.LOW,
            stage_confidence=0.70,
            topology_availability=TopologyAvailability.KNOWN,
        )
        dec = self.engine.evaluate(inp)
        # Even with risk=0.85, execution and preparation are strictly blocked
        self.assertIn(ActionClass.EXECUTE_REVERSIBLE_ACTION, dec.blocked_action_classes)
        self.assertIn(ActionClass.PREPARE_REVERSIBLE_ACTION, dec.blocked_action_classes)
        self.assertIn(ActionClass.GENERATE_RECOMMENDATION, dec.blocked_action_classes)
        self.assertNotIn(dec.authority_level, (AuthorityLevel.RECOMMEND, AuthorityLevel.HUMAN_APPROVAL_REQUIRED))
        self.assertIn("LOW_TRUST_BLOCKS_RECOMMENDATION", dec.reason_codes)

    # 4. Insufficient Trust Constrains Authority
    def test_insufficient_trust_constrains_authority(self) -> None:
        inp = self._base_valid_input(
            risk_score=0.90,
            composite_trust=0.10,
            uncertainty=0.15,
            trust_level=TrustLevel.INSUFFICIENT,
            stage_confidence=0.80,
        )
        dec = self.engine.evaluate(inp)
        self.assertIn(ActionClass.EXECUTE_REVERSIBLE_ACTION, dec.blocked_action_classes)
        self.assertIn(ActionClass.PREPARE_REVERSIBLE_ACTION, dec.blocked_action_classes)
        self.assertIn(ActionClass.GENERATE_RECOMMENDATION, dec.blocked_action_classes)

    # 5. High Uncertainty Constrains Authority
    def test_high_uncertainty_constrains_authority(self) -> None:
        inp = self._base_valid_input(
            risk_score=0.75,
            composite_trust=0.85,  # High trust
            uncertainty=0.60,      # But high uncertainty!
            trust_level=TrustLevel.HIGH,
            stage_confidence=0.70,
        )
        dec = self.engine.evaluate(inp)
        self.assertIn(ActionClass.EXECUTE_REVERSIBLE_ACTION, dec.blocked_action_classes)
        self.assertIn(ActionClass.PREPARE_REVERSIBLE_ACTION, dec.blocked_action_classes)
        self.assertIn(ActionClass.GENERATE_RECOMMENDATION, dec.blocked_action_classes)

    # 6. Topology UNAVAILABLE Blocks Execution and Preparation
    def test_topology_unavailable_blocks_execution_and_preparation(self) -> None:
        inp = self._base_valid_input(
            risk_score=0.70,
            composite_trust=0.85,
            uncertainty=0.15,
            trust_level=TrustLevel.HIGH,
            stage_confidence=0.80,
            topology_availability=TopologyAvailability.UNAVAILABLE,
        )
        dec = self.engine.evaluate(inp)
        self.assertIn(ActionClass.EXECUTE_REVERSIBLE_ACTION, dec.blocked_action_classes)
        self.assertIn(ActionClass.PREPARE_REVERSIBLE_ACTION, dec.blocked_action_classes)
        self.assertIn("UNAVAILABLE_TOPOLOGY_BLOCKS_EXECUTION", dec.reason_codes)
        self.assertIn("UNAVAILABLE_TOPOLOGY_BLOCKS_PREPARATION", dec.reason_codes)

    # 7. PARTIAL Topology Mandates Human Approval
    def test_partial_topology_mandates_human_approval(self) -> None:
        inp = self._base_valid_input(
            risk_score=0.65,
            composite_trust=0.80,
            uncertainty=0.15,
            trust_level=TrustLevel.HIGH,
            stage_confidence=0.75,
            topology_availability=TopologyAvailability.PARTIAL,
        )
        dec = self.engine.evaluate(inp)
        self.assertTrue(dec.human_approval_required)
        self.assertEqual(dec.authority_level, AuthorityLevel.HUMAN_APPROVAL_REQUIRED)
        self.assertIn("PARTIAL_TOPOLOGY_REQUIRES_HUMAN_APPROVAL", dec.reason_codes)

    # 8. Destructive Actions Are Always Blocked
    def test_destructive_action_always_blocked(self) -> None:
        inp = self._base_valid_input(
            risk_score=0.99,
            composite_trust=0.99,
            uncertainty=0.01,
            trust_level=TrustLevel.HIGH,
            stage_confidence=0.99,
            topology_availability=TopologyAvailability.KNOWN,
        )
        dec = self.engine.evaluate(inp)
        self.assertIn(ActionClass.EXECUTE_DESTRUCTIVE_ACTION, dec.blocked_action_classes)
        self.assertNotIn(ActionClass.EXECUTE_DESTRUCTIVE_ACTION, dec.permitted_action_classes)
        self.assertIn("DESTRUCTIVE_ACTIONS_PERMANENTLY_BLOCKED", dec.reason_codes)

    def test_destructive_action_requested_returns_blocked(self) -> None:
        inp = self._base_valid_input(
            risk_score=0.99,
            composite_trust=0.99,
            uncertainty=0.01,
            requested_action_class=ActionClass.EXECUTE_DESTRUCTIVE_ACTION,
        )
        dec = self.engine.evaluate(inp)
        self.assertEqual(dec.authority_level, AuthorityLevel.BLOCKED)

    # 9. High Blast Radius Urgency Without Authority Expansion
    def test_high_blast_radius_urgency_without_authority_expansion(self) -> None:
        # High blast radius with low trust -> urgency increases, but authority does NOT expand!
        inp = AuthorityPolicyInput(
            risk_score=0.60,
            forecast_trust=0.30,
            composite_trust=0.30,
            uncertainty=0.25,
            trust_level=TrustLevel.LOW,
            stage_confidence=0.60,
            topology_availability=TopologyAvailability.KNOWN,
            blast_radius_status=BlastRadiusStatus.COMPLETE,
            blast_radius_coverage=1.0,
            affected_node_count=10,
            critical_affected_node_count=4,
            weighted_structural_impact=0.90,  # Extreme blast radius
        )
        dec = self.engine.evaluate(inp)
        self.assertTrue(dec.human_approval_required)
        self.assertIn("HIGH_STRUCTURAL_BLAST_RADIUS_URGENCY", dec.reason_codes)
        # Authority must NOT expand to execute reversible action due to low trust
        self.assertIn(ActionClass.EXECUTE_REVERSIBLE_ACTION, dec.blocked_action_classes)
        self.assertNotIn(dec.authority_level, (AuthorityLevel.HUMAN_APPROVAL_REQUIRED, AuthorityLevel.RECOMMEND))

    # 10. Principle: HIGH RISK != HIGH AUTHORITY (Case A vs. Case B)
    def test_risk_vs_authority_separation_case_a(self) -> None:
        """Case A: High Risk (0.92) + Low Trust (0.25) + High Uncertainty (0.65)."""
        inp_a = self._base_valid_input(
            risk_score=0.92,
            composite_trust=0.25,
            uncertainty=0.65,
            trust_level=TrustLevel.LOW,
            stage_confidence=0.85,
            topology_availability=TopologyAvailability.KNOWN,
        )
        dec_a = self.engine.evaluate(inp_a)
        # High risk must not grant execution authority
        self.assertIn(ActionClass.EXECUTE_REVERSIBLE_ACTION, dec_a.blocked_action_classes)
        self.assertEqual(dec_a.authority_level, AuthorityLevel.ALERT)

    def test_risk_vs_authority_separation_case_b(self) -> None:
        """Case B: Moderate Risk (0.40) + High Trust (0.85) + Low Uncertainty (0.15)."""
        inp_b = self._base_valid_input(
            risk_score=0.40,
            composite_trust=0.85,
            uncertainty=0.15,
            trust_level=TrustLevel.HIGH,
            stage_confidence=0.70,
            topology_availability=TopologyAvailability.KNOWN,
        )
        dec_b = self.engine.evaluate(inp_b)
        # Moderate risk with high evidence quality permits reversible execution (human-gated)
        self.assertIn(ActionClass.EXECUTE_REVERSIBLE_ACTION, dec_b.permitted_action_classes)
        self.assertEqual(dec_b.authority_level, AuthorityLevel.HUMAN_APPROVAL_REQUIRED)

    # 11. Monotonicity Guarantees
    def test_monotonicity_trust(self) -> None:
        """Higher trust should never reduce permitted action classes."""
        levels = [
            (0.20, TrustLevel.LOW),
            (0.50, TrustLevel.MEDIUM),
            (0.80, TrustLevel.HIGH),
        ]
        prev_perm_count = 0
        for trust_val, lvl in levels:
            inp = self._base_valid_input(
                risk_score=0.50,
                composite_trust=trust_val,
                uncertainty=0.20,
                trust_level=lvl,
                stage_confidence=0.60,
                topology_availability=TopologyAvailability.KNOWN,
            )
            dec = self.engine.evaluate(inp)
            perm_count = len(dec.permitted_action_classes)
            self.assertGreaterEqual(perm_count, prev_perm_count)
            prev_perm_count = perm_count

    def test_monotonicity_uncertainty(self) -> None:
        """Higher uncertainty should never increase permitted action classes."""
        uncertainties = [0.10, 0.30, 0.55, 0.85]
        prev_perm_count = 999
        for unc in uncertainties:
            inp = self._base_valid_input(
                risk_score=0.60,
                composite_trust=0.80,
                uncertainty=unc,
                trust_level=TrustLevel.HIGH,
                stage_confidence=0.70,
                topology_availability=TopologyAvailability.KNOWN,
            )
            dec = self.engine.evaluate(inp)
            perm_count = len(dec.permitted_action_classes)
            self.assertLessEqual(perm_count, prev_perm_count)
            prev_perm_count = perm_count

    def test_monotonicity_topology(self) -> None:
        """Improving topology availability should never decrease permitted action classes."""
        topologies = [
            TopologyAvailability.UNAVAILABLE,
            TopologyAvailability.PARTIAL,
            TopologyAvailability.KNOWN,
        ]
        prev_perm_count = 0
        for topo in topologies:
            inp = self._base_valid_input(
                risk_score=0.65,
                composite_trust=0.80,
                uncertainty=0.15,
                trust_level=TrustLevel.HIGH,
                stage_confidence=0.70,
                topology_availability=topo,
            )
            dec = self.engine.evaluate(inp)
            perm_count = len(dec.permitted_action_classes)
            self.assertGreaterEqual(perm_count, prev_perm_count)
            prev_perm_count = perm_count

    # 12. Fail-Closed Handling & Missing Explicit Uncertainty
    def test_fail_closed_missing_uncertainty(self) -> None:
        """Missing explicit uncertainty fails closed rather than synthesizing a metric."""
        inp = AuthorityPolicyInput(
            risk_score=0.70,
            forecast_trust=0.85,
            composite_trust=0.85,
            uncertainty=None,  # No uncertainty provided!
            trust_level=TrustLevel.HIGH,
            stage_confidence=0.75,
            topology_availability=TopologyAvailability.KNOWN,
        )
        self.assertFalse(inp.is_valid())
        dec = self.engine.evaluate(inp)
        self.assertEqual(dec.authority_level, AuthorityLevel.OBSERVE)
        self.assertEqual(dec.permitted_action_classes, (ActionClass.OBSERVE_ONLY,))
        self.assertIn("FAIL_CLOSED_INVALID_OR_MISSING_INPUT", dec.reason_codes)

    def test_fail_closed_nan_uncertainty(self) -> None:
        inp = self._base_valid_input(uncertainty=float("nan"))
        self.assertFalse(inp.is_valid())
        dec = self.engine.evaluate(inp)
        self.assertEqual(dec.authority_level, AuthorityLevel.OBSERVE)
        self.assertIn("FAIL_CLOSED_INVALID_OR_MISSING_INPUT", dec.reason_codes)

    def test_fail_closed_out_of_bounds_scores(self) -> None:
        inp = self._base_valid_input(risk_score=1.5)
        self.assertFalse(inp.is_valid())
        dec = self.engine.evaluate(inp)
        self.assertEqual(dec.authority_level, AuthorityLevel.OBSERVE)

        inp_neg = self._base_valid_input(composite_trust=-0.2)
        self.assertFalse(inp_neg.is_valid())
        dec_neg = self.engine.evaluate(inp_neg)
        self.assertEqual(dec_neg.authority_level, AuthorityLevel.OBSERVE)

    # 13. Horizon-Specific Uncertainty Reuse
    def test_horizon_specific_uncertainty_reuse(self) -> None:
        """Reuses explicit horizon-specific uncertainty from horizon_uncertainties mapping."""
        inp = AuthorityPolicyInput(
            risk_score=0.60,
            forecast_trust=0.85,
            composite_trust=0.85,
            uncertainty=None,
            trust_level=TrustLevel.HIGH,
            stage_confidence=0.70,
            topology_availability=TopologyAvailability.KNOWN,
            horizon_step=1,
            horizon_uncertainties={0: 0.15, 1: 0.22, 2: 0.35},
        )
        self.assertTrue(inp.is_valid())
        self.assertEqual(inp.effective_uncertainty, 0.22)
        dec = self.engine.evaluate(inp)
        self.assertEqual(dec.authority_level, AuthorityLevel.HUMAN_APPROVAL_REQUIRED)
        self.assertIn(ActionClass.EXECUTE_REVERSIBLE_ACTION, dec.permitted_action_classes)

    # 14. Reconsideration Integration
    def test_reconsideration_flag_tracked_and_evaluated(self) -> None:
        inp = self._base_valid_input(is_reconsideration=True)
        dec = self.engine.evaluate(inp)
        self.assertIn("RECONSIDERED_EVIDENCE_EVALUATED", dec.reason_codes)

    # 15. Deterministic Provenance Hashes & Serialization
    def test_deterministic_provenance_hash(self) -> None:
        inp = self._base_valid_input()
        dec1 = self.engine.evaluate(inp)
        dec2 = self.engine.evaluate(inp)
        self.assertTrue(dec1.provenance_hash)
        self.assertEqual(dec1.provenance_hash, dec2.provenance_hash)

    def test_provenance_hash_varies_with_decision(self) -> None:
        inp1 = self._base_valid_input(composite_trust=0.85, uncertainty=0.15)
        inp2 = self._base_valid_input(composite_trust=0.30, uncertainty=0.70)
        dec1 = self.engine.evaluate(inp1)
        dec2 = self.engine.evaluate(inp2)
        self.assertNotEqual(dec1.provenance_hash, dec2.provenance_hash)

    def test_decision_serialization_roundtrip(self) -> None:
        inp = self._base_valid_input()
        dec = self.engine.evaluate(inp)
        d = dec.to_dict()
        self.assertEqual(d["authority_level"], dec.authority_level.value)
        self.assertEqual(d["provenance_hash"], dec.provenance_hash)

        reconstituted = AuthorityDecision.from_dict(d)
        self.assertEqual(reconstituted.authority_level, dec.authority_level)
        self.assertEqual(reconstituted.permitted_action_classes, dec.permitted_action_classes)
        self.assertEqual(reconstituted.blocked_action_classes, dec.blocked_action_classes)
        self.assertEqual(reconstituted.provenance_hash, dec.provenance_hash)

    # 16. Invariance: Risk, Priority, and Recommendations Remain Unmutated
    def test_risk_and_priority_scores_remain_invariant(self) -> None:
        """Evaluating authority policy does NOT modify or rescale risk or priority scores."""
        orig_risk = 0.65
        orig_trust = 0.80
        inp = self._base_valid_input(risk_score=orig_risk, composite_trust=orig_trust)
        dec = self.engine.evaluate(inp)
        # Original inputs are immutable dataclass
        self.assertEqual(inp.risk_score, orig_risk)
        self.assertEqual(inp.composite_trust, orig_trust)
        self.assertIsInstance(dec, AuthorityDecision)

    # 17. End-to-End DemoEvent Integration
    def test_demo_event_authority_policy_integration(self) -> None:
        """Verify LiveDemoEngine streams events with attached authority_policy payload."""
        from scenarios.demo.scenarios import get_demo_scenario_states

        engine = LiveDemoEngine()
        states = get_demo_scenario_states("demo_recon_15s")[:4]
        events = list(engine.stream_scenario(states))
        self.assertEqual(len(events), 4)
        for ev in events:
            self.assertIsInstance(ev, DemoEvent)
            self.assertIsNotNone(ev.authority_policy)
            auth_d = ev.authority_policy
            self.assertIn("authority_level", auth_d)
            self.assertIn("permitted_action_classes", auth_d)
            self.assertIn("blocked_action_classes", auth_d)
            self.assertIn("provenance_hash", auth_d)
            # Destructive action must always be blocked
            self.assertIn("EXECUTE_DESTRUCTIVE_ACTION", auth_d["blocked_action_classes"])
            # Serialization round-trip
            ev_dict = ev.to_dict()
            self.assertIn("authority_policy", ev_dict)
            self.assertEqual(ev_dict["authority_policy"], auth_d)

    # 18. Full Risk x Trust x Uncertainty x Topology Matrix
    def test_full_risk_trust_uncertainty_topology_matrix(self) -> None:
        """Matrix test covering multi-dimensional state space permutations."""
        scenarios = [
            # (risk, trust, unc, stage_conf, topo, expected_auth_level, execute_rev_blocked)
            (0.85, 0.90, 0.10, 0.70, TopologyAvailability.KNOWN, AuthorityLevel.HUMAN_APPROVAL_REQUIRED, False),
            (0.85, 0.30, 0.10, 0.70, TopologyAvailability.KNOWN, AuthorityLevel.ALERT, True),
            (0.85, 0.90, 0.65, 0.70, TopologyAvailability.KNOWN, AuthorityLevel.ALERT, True),
            (0.85, 0.90, 0.10, 0.70, TopologyAvailability.UNAVAILABLE, AuthorityLevel.RECOMMEND, True),
            (0.10, 0.90, 0.10, 0.70, TopologyAvailability.KNOWN, AuthorityLevel.HUMAN_APPROVAL_REQUIRED, False),
            (0.10, 0.50, 0.30, 0.40, TopologyAvailability.KNOWN, AuthorityLevel.RECOMMEND, True),
            (0.10, 0.90, 0.10, 0.20, TopologyAvailability.KNOWN, AuthorityLevel.HUMAN_APPROVAL_REQUIRED, True),
            (0.10, 0.20, 0.80, 0.10, TopologyAvailability.UNAVAILABLE, AuthorityLevel.OBSERVE, True),
        ]
        for risk, trust, unc, stage_conf, topo, exp_level, exp_exec_blocked in scenarios:
            t_lvl = TrustLevel.HIGH if trust >= 0.70 else (TrustLevel.MEDIUM if trust >= 0.45 else TrustLevel.LOW)
            aff_nodes = 0 if (risk < 0.15 and stage_conf < 0.30) else 2
            inp = self._base_valid_input(
                risk_score=risk,
                composite_trust=trust,
                uncertainty=unc,
                trust_level=t_lvl,
                stage_confidence=stage_conf,
                topology_availability=topo,
                affected_node_count=aff_nodes,
            )
            dec = self.engine.evaluate(inp)
            self.assertEqual(
                dec.authority_level,
                exp_level,
                f"Failed for risk={risk}, trust={trust}, unc={unc}, topo={topo}",
            )
            is_exec_blocked = ActionClass.EXECUTE_REVERSIBLE_ACTION in dec.blocked_action_classes
            self.assertEqual(
                is_exec_blocked,
                exp_exec_blocked,
                f"Execution blocking mismatch for risk={risk}, trust={trust}, unc={unc}, topo={topo}",
            )


if __name__ == "__main__":
    unittest.main()
