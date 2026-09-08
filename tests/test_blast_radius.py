"""Comprehensive Test Suite for Blast Radius & Impact Analysis (SIH 26153 Task 19).

Validates:
1. Basic blast-radius assessment & schema integrity
2. Direct dependents query
3. Transitive dependents query
4. Correct root node exclusion (never counts root as dependent)
5. Dependency depth calculation (BFS shortest-path distance)
6. Criticality metadata extraction
7. Weighted structural impact heuristic score & safe zero-denominator handling
8. KNOWN topology coverage (coverage_ratio == 1.0, is_complete == True)
9. PARTIAL topology handling (status == PARTIAL, indeterminate coverage_ratio is None)
10. UNAVAILABLE topology handling (explicit UNKNOWN status, NOT zero impact)
11. Root node not found handling (ROOT_NOT_FOUND, no node fabrication)
12. Cycle safety & termination (no infinite loops, no duplicate nodes)
13. Duplicate-free affected-node sets
14. Deterministic traversal ordering
15. Deterministic provenance hash
16. Critical and high-criticality affected-node classification
17. Mandatory Test Case 1: Gateway -> API -> Auth -> Database (Root = Database)
18. Mandatory Test Case 2: Cyclic Graph A -> B -> C -> A (Root = A)
19. DemoEvent integration & backward compatibility
20. Invariance: Blast radius does NOT modify risk or priority scores
21. Non-autonomous: Blast radius does NOT execute containment actions
22. Reconsideration integrity: Task 17 reconsideration remains fully functional
"""
from __future__ import annotations

import unittest
from datetime import datetime

from core.blastradius.engine import BlastRadiusEngine
from core.blastradius.models import BlastRadiusAssessment, BlastRadiusStatus
from core.topology.builder import (
    build_enterprise_demo_topology,
    build_minimal_demo_topology,
    build_unavailable_topology,
)
from core.topology.graph import ServiceTopologyGraph
from core.topology.models import (
    CriticalityLevel,
    DependencyEdge,
    DependencyType,
    ServiceNode,
    ServiceType,
    TopologyAvailability,
)
from scenarios.demo.engine import DemoEvent, LiveDemoEngine
from scenarios.demo.scenarios import get_demo_scenario_states


class TestBlastRadius(unittest.TestCase):
    """Dedicated test suite for Task 19 Blast Radius & Impact Analysis."""

    def setUp(self) -> None:
        self.engine = BlastRadiusEngine()

    def test_01_basic_blast_radius_assessment(self) -> None:
        """Verify basic assessment execution, attributes, and serialization roundtrip."""
        topo = build_minimal_demo_topology()
        assessment = self.engine.assess(topo, root_node_id="svc-db")

        self.assertIsInstance(assessment, BlastRadiusAssessment)
        self.assertEqual(assessment.root_node_id, "svc-db")
        self.assertEqual(assessment.status, BlastRadiusStatus.COMPLETE)
        self.assertTrue(assessment.is_complete)
        self.assertEqual(assessment.coverage_ratio, 1.0)
        self.assertEqual(len(assessment.provenance_hash), 64)
        self.assertIn("Structural blast radius assessment", assessment.explanation)

        # Serialization roundtrip
        d = assessment.to_dict()
        self.assertEqual(d["root_node_id"], "svc-db")
        self.assertEqual(d["status"], "COMPLETE")
        self.assertEqual(d["affected_node_count"], assessment.affected_node_count)

        restored = BlastRadiusAssessment.from_dict(d)
        self.assertEqual(restored.root_node_id, assessment.root_node_id)
        self.assertEqual(restored.affected_node_ids, assessment.affected_node_ids)
        self.assertEqual(restored.weighted_impact_score, assessment.weighted_impact_score)

    def test_02_direct_dependents(self) -> None:
        """Verify immediate downstream dependents of root node."""
        topo = build_minimal_demo_topology()
        # In API -> Auth -> DB:
        # DB's direct dependent is Auth
        assessment_db = self.engine.assess(topo, "svc-db")
        self.assertEqual(assessment_db.direct_dependent_ids, ("svc-auth",))

        # Auth's direct dependent is API
        assessment_auth = self.engine.assess(topo, "svc-auth")
        self.assertEqual(assessment_auth.direct_dependent_ids, ("svc-api",))

        # API has no dependents
        assessment_api = self.engine.assess(topo, "svc-api")
        self.assertEqual(assessment_api.direct_dependent_ids, ())

    def test_03_transitive_dependents(self) -> None:
        """Verify multi-hop downstream dependents."""
        topo = build_minimal_demo_topology()
        assessment_db = self.engine.assess(topo, "svc-db")
        # DB has transitive dependents: Auth (direct), API (multi-hop)
        self.assertEqual(set(assessment_db.transitive_dependent_ids), {"svc-auth", "svc-api"})
        self.assertEqual(assessment_db.affected_node_count, 2)

    def test_04_root_exclusion(self) -> None:
        """Verify root node is never counted in affected dependents."""
        topo = build_minimal_demo_topology()
        for root_id in ["svc-api", "svc-auth", "svc-db"]:
            assessment = self.engine.assess(topo, root_id)
            self.assertNotIn(root_id, assessment.affected_node_ids)
            self.assertNotIn(root_id, assessment.direct_dependent_ids)
            self.assertNotIn(root_id, assessment.transitive_dependent_ids)
            self.assertNotIn(root_id, assessment.node_depths)

    def test_05_dependency_depth(self) -> None:
        """Verify exact BFS shortest-path dependency depth mapping."""
        topo = build_minimal_demo_topology()
        assessment = self.engine.assess(topo, "svc-db")
        # DB -> Auth (depth 1) -> API (depth 2)
        self.assertEqual(assessment.node_depths["svc-auth"], 1)
        self.assertEqual(assessment.node_depths["svc-api"], 2)
        self.assertEqual(assessment.maximum_dependency_depth, 2)

    def test_06_criticality_extraction(self) -> None:
        """Verify criticality metadata is preserved and classified."""
        topo = build_enterprise_demo_topology()
        # Evaluate customer DB
        assessment = self.engine.assess(topo, "svc-customer-db")
        # Critical dependents (criticality >= 0.85)
        for nid in assessment.critical_affected_node_ids:
            node = topo.get_node(nid)
            self.assertTrue(node.criticality >= 0.85 or node.criticality_level == CriticalityLevel.CRITICAL)

    def test_07_weighted_structural_impact_score(self) -> None:
        """Verify weighted structural impact heuristic and safe zero-denominator handling."""
        topo = build_minimal_demo_topology()
        assessment_db = self.engine.assess(topo, "svc-db")
        # Score must be bounded in [0.0, 1.0]
        self.assertTrue(0.0 <= assessment_db.weighted_impact_score <= 1.0)
        # DB affects all other nodes in minimal demo (Auth + API), so score must be 1.0
        self.assertAlmostEqual(assessment_db.weighted_impact_score, 1.0, places=4)

        # Isolated leaf node: API has 0 dependents -> impact must be 0.0
        assessment_api = self.engine.assess(topo, "svc-api")
        self.assertEqual(assessment_api.weighted_impact_score, 0.0)

        # Zero denominator safety test: Single node graph
        solo_graph = ServiceTopologyGraph()
        solo_graph.add_node(ServiceNode("solo", "Solo", ServiceType.DATABASE, 0.5, CriticalityLevel.MEDIUM))
        assessment_solo = self.engine.assess(solo_graph, "solo")
        self.assertEqual(assessment_solo.weighted_impact_score, 0.0)
        self.assertEqual(assessment_solo.affected_node_count, 0)

    def test_08_known_topology_coverage(self) -> None:
        """Verify KNOWN topology yields coverage_ratio == 1.0 and is_complete == True."""
        topo = build_minimal_demo_topology()
        self.assertEqual(topo.availability, TopologyAvailability.KNOWN)

        assessment = self.engine.assess(topo, "svc-db")
        self.assertEqual(assessment.status, BlastRadiusStatus.COMPLETE)
        self.assertEqual(assessment.coverage_ratio, 1.0)
        self.assertTrue(assessment.is_complete)

    def test_09_partial_topology_incomplete_marking(self) -> None:
        """Verify PARTIAL topology does NOT invent coverage numbers (coverage_ratio is None)."""
        node_a = ServiceNode("a", "Node A", ServiceType.API, 0.5, CriticalityLevel.MEDIUM)
        node_b = ServiceNode("b", "Node B", ServiceType.DATABASE, 0.5, CriticalityLevel.MEDIUM)
        partial_graph = ServiceTopologyGraph.create_partial(
            nodes=[node_a, node_b],
            edges=[DependencyEdge("a", "b")],
            reason="Partial packet capture observation",
        )
        self.assertEqual(partial_graph.availability, TopologyAvailability.PARTIAL)

        assessment = self.engine.assess(partial_graph, "b")
        self.assertEqual(assessment.status, BlastRadiusStatus.PARTIAL)
        self.assertIsNone(assessment.coverage_ratio)
        self.assertFalse(assessment.is_complete)
        self.assertIn("PARTIAL", assessment.explanation)
        self.assertIn("indeterminate", assessment.explanation)

    def test_10_unavailable_topology_unknown_not_zero(self) -> None:
        """Verify UNAVAILABLE topology explicitly signals UNKNOWN, not zero impact."""
        unavail = build_unavailable_topology("NetFlow telemetry lacks host endpoint topology")
        assessment = self.engine.assess(unavail, "any-node")

        self.assertEqual(assessment.status, BlastRadiusStatus.UNAVAILABLE)
        self.assertEqual(assessment.coverage_ratio, 0.0)
        self.assertFalse(assessment.is_complete)
        self.assertEqual(assessment.affected_node_count, 0)
        self.assertIn("UNAVAILABLE", assessment.explanation)
        self.assertIn("UNKNOWN", assessment.explanation)

    def test_11_root_node_not_found(self) -> None:
        """Verify missing root node produces explicit ROOT_NOT_FOUND without node fabrication."""
        topo = build_minimal_demo_topology()
        assessment = self.engine.assess(topo, "non-existent-node")

        self.assertEqual(assessment.status, BlastRadiusStatus.ROOT_NOT_FOUND)
        self.assertEqual(assessment.coverage_ratio, 0.0)
        self.assertFalse(assessment.is_complete)
        self.assertEqual(assessment.affected_node_count, 0)
        self.assertIn("not found in the topology graph", assessment.explanation)

    def test_12_cycle_safety(self) -> None:
        """Verify cycle safety and termination on cyclic dependency graph."""
        graph = ServiceTopologyGraph()
        for nid in ["node-a", "node-b", "node-c"]:
            graph.add_node(ServiceNode(nid, nid, ServiceType.INTERNAL_SERVICE, 0.5, CriticalityLevel.MEDIUM))

        # Cycle: A -> B -> C -> A
        graph.add_dependency("node-a", "node-b")
        graph.add_dependency("node-b", "node-c")
        graph.add_dependency("node-c", "node-a")

        # Assess with root = node-a
        # Dependents of A: C (since C depends on A)
        # Dependents of C: B (since B depends on C)
        assessment = self.engine.assess(graph, "node-a")
        self.assertEqual(assessment.status, BlastRadiusStatus.COMPLETE)
        self.assertEqual(set(assessment.affected_node_ids), {"node-b", "node-c"})
        self.assertNotIn("node-a", assessment.affected_node_ids)
        self.assertEqual(assessment.affected_node_count, 2)

    def test_13_duplicate_free_affected_nodes(self) -> None:
        """Verify affected node list contains no duplicates even with multiple paths."""
        graph = ServiceTopologyGraph()
        # Diamond dependency:
        # D depends on B and C
        # B depends on A
        # C depends on A
        for nid in ["a", "b", "c", "d"]:
            graph.add_node(ServiceNode(nid, nid, ServiceType.INTERNAL_SERVICE, 0.5, CriticalityLevel.MEDIUM))

        graph.add_dependency("b", "a")
        graph.add_dependency("c", "a")
        graph.add_dependency("d", "b")
        graph.add_dependency("d", "c")

        assessment = self.engine.assess(graph, "a")
        # Dependents of A: B, C (depth 1), D (depth 2)
        self.assertEqual(len(assessment.affected_node_ids), len(set(assessment.affected_node_ids)))
        self.assertEqual(assessment.affected_node_count, 3)
        self.assertEqual(set(assessment.affected_node_ids), {"b", "c", "d"})
        self.assertEqual(assessment.node_depths["d"], 2)

    def test_14_deterministic_ordering(self) -> None:
        """Verify deterministic ordering of affected nodes across multiple evaluations."""
        topo = build_enterprise_demo_topology()
        first_run = self.engine.assess(topo, "svc-customer-db")

        for _ in range(5):
            repeated_run = self.engine.assess(topo, "svc-customer-db")
            self.assertEqual(first_run.affected_node_ids, repeated_run.affected_node_ids)
            self.assertEqual(first_run.direct_dependent_ids, repeated_run.direct_dependent_ids)
            self.assertEqual(first_run.node_depths, repeated_run.node_depths)

    def test_15_deterministic_provenance(self) -> None:
        """Verify provenance hash is deterministic and reproducible."""
        topo = build_minimal_demo_topology()
        snap_id = "test-snap-001"
        a1 = self.engine.assess(topo, "svc-db", snapshot_id=snap_id)
        a2 = self.engine.assess(topo, "svc-db", snapshot_id=snap_id)
        self.assertEqual(a1.provenance_hash, a2.provenance_hash)

    def test_16_critical_and_high_criticality_filtering(self) -> None:
        """Verify correct filtering of critical and high-criticality affected nodes."""
        graph = ServiceTopologyGraph()
        graph.add_node(ServiceNode("root", "Root", ServiceType.DATABASE, 0.9, CriticalityLevel.CRITICAL))
        graph.add_node(ServiceNode("crit-dep", "Critical", ServiceType.AUTH, 0.95, CriticalityLevel.CRITICAL))
        graph.add_node(ServiceNode("high-dep", "High", ServiceType.API, 0.75, CriticalityLevel.HIGH))
        graph.add_node(ServiceNode("low-dep", "Low", ServiceType.CACHE, 0.20, CriticalityLevel.LOW))

        graph.add_dependency("crit-dep", "root")
        graph.add_dependency("high-dep", "crit-dep")
        graph.add_dependency("low-dep", "high-dep")

        assessment = self.engine.assess(graph, "root")
        self.assertEqual(assessment.critical_affected_node_ids, ("crit-dep",))
        self.assertEqual(assessment.high_criticality_affected_node_ids, ("high-dep",))

    def test_17_mandatory_case_gateway_api_auth_db(self) -> None:
        """
        Mandatory Test Case 1:
        Gateway -> API -> Auth -> Database
        Root: Database
        Expected:
            root: Database
            direct: Auth
            transitive: Auth, API, Gateway
            depth: Auth=1, API=2, Gateway=3
            affected count: 3
            Database itself NOT counted.
        """
        graph = ServiceTopologyGraph()
        nodes = [
            ServiceNode("Gateway", "Gateway", ServiceType.GATEWAY, 0.85, CriticalityLevel.CRITICAL),
            ServiceNode("API", "API", ServiceType.API, 0.80, CriticalityLevel.HIGH),
            ServiceNode("Auth", "Auth", ServiceType.AUTH, 0.90, CriticalityLevel.CRITICAL),
            ServiceNode("Database", "Database", ServiceType.DATABASE, 0.95, CriticalityLevel.CRITICAL),
        ]
        for n in nodes:
            graph.add_node(n)

        # Gateway -> API -> Auth -> Database
        graph.add_dependency("Gateway", "API")
        graph.add_dependency("API", "Auth")
        graph.add_dependency("Auth", "Database")

        assessment = self.engine.assess(graph, "Database")

        # Verifications
        self.assertEqual(assessment.root_node_id, "Database")
        self.assertEqual(assessment.direct_dependent_ids, ("Auth",))
        self.assertEqual(set(assessment.transitive_dependent_ids), {"Auth", "API", "Gateway"})
        self.assertEqual(assessment.affected_node_count, 3)
        self.assertNotIn("Database", assessment.affected_node_ids)

        # Depths
        self.assertEqual(assessment.node_depths["Auth"], 1)
        self.assertEqual(assessment.node_depths["API"], 2)
        self.assertEqual(assessment.node_depths["Gateway"], 3)
        self.assertEqual(assessment.maximum_dependency_depth, 3)

    def test_18_mandatory_case_cyclic_graph(self) -> None:
        """
        Mandatory Test Case 2:
        Cycle: A -> B -> C -> A
        Root: A
        Expected:
            affected dependents: B, C
            No duplicates, no infinite loop.
        """
        graph = ServiceTopologyGraph()
        for nid in ["A", "B", "C"]:
            graph.add_node(ServiceNode(nid, nid, ServiceType.INTERNAL_SERVICE, 0.5, CriticalityLevel.MEDIUM))

        # A -> B -> C -> A
        graph.add_dependency("A", "B")
        graph.add_dependency("B", "C")
        graph.add_dependency("C", "A")

        assessment = self.engine.assess(graph, "A")

        # In A -> B -> C -> A:
        # A depends on B, B depends on C, C depends on A.
        # Who depends on A? C depends on A (depth 1).
        # Who depends on C? B depends on C (depth 2).
        # Who depends on B? A depends on B (cycle back to root, excluded).
        self.assertEqual(set(assessment.affected_node_ids), {"B", "C"})
        self.assertNotIn("A", assessment.affected_node_ids)
        self.assertEqual(assessment.affected_node_count, 2)
        self.assertEqual(len(assessment.affected_node_ids), len(set(assessment.affected_node_ids)))

    def test_19_demo_event_integration(self) -> None:
        """Verify DemoEvent carries blast_radius when topology is provided, None otherwise."""
        states = get_demo_scenario_states("demo_recon_15s")[:3]
        demo_topo = build_minimal_demo_topology()

        # With topology
        engine_with_topo = LiveDemoEngine(topology=demo_topo, focus_node_id="svc-db")
        events_with_topo = list(engine_with_topo.stream_scenario(states))
        first_event = events_with_topo[0]

        self.assertIsNotNone(first_event.blast_radius)
        self.assertEqual(first_event.blast_radius["root_node_id"], "svc-db")
        self.assertEqual(first_event.blast_radius["affected_node_count"], 2)
        self.assertEqual(first_event.blast_radius["maximum_dependency_depth"], 2)

        # Without topology (backward compatibility)
        engine_no_topo = LiveDemoEngine(topology=None)
        events_no_topo = list(engine_no_topo.stream_scenario(states))
        self.assertIsNone(events_no_topo[0].blast_radius)

    def test_20_blast_radius_does_not_modify_risk_or_priority(self) -> None:
        """CRITICAL INVARIANT: Blast radius MUST NOT alter risk, priority, or response scores."""
        states = get_demo_scenario_states("demo_recon_15s")[:10]
        demo_topo = build_enterprise_demo_topology()

        engine_baseline = LiveDemoEngine(topology=None)
        engine_with_br = LiveDemoEngine(topology=demo_topo, focus_node_id="svc-customer-db")

        events_baseline = list(engine_baseline.stream_scenario(states))
        events_with_br = list(engine_with_br.stream_scenario(states))

        for idx, (b_evt, br_evt) in enumerate(zip(events_baseline, events_with_br)):
            # Risk scores must remain exact
            self.assertAlmostEqual(b_evt.current_risk_score, br_evt.current_risk_score, places=5)
            self.assertEqual(b_evt.future_risk_scores, br_evt.future_risk_scores)
            # Priority levels and composite priority must remain exact
            self.assertEqual(b_evt.priority_level, br_evt.priority_level)
            self.assertAlmostEqual(b_evt.composite_priority, br_evt.composite_priority, places=5)
            # Recommendation must remain exact
            self.assertEqual(b_evt.recommended_strategy, br_evt.recommended_strategy)
            self.assertEqual(b_evt.recommended_actions, br_evt.recommended_actions)

    def test_21_blast_radius_does_not_execute_actions(self) -> None:
        """Verify blast radius is purely analytical and does not trigger actions."""
        topo = build_minimal_demo_topology()
        assessment = self.engine.assess(topo, "svc-db")
        # Assessment must only contain data, no action execution side-effects
        self.assertIsInstance(assessment, BlastRadiusAssessment)
        self.assertFalse(hasattr(assessment, "execute"))
        self.assertFalse(hasattr(assessment, "isolate"))

    def test_22_reconsideration_remains_functional(self) -> None:
        """Verify Task 17 reconsideration behavior remains active with blast radius enabled."""
        states = get_demo_scenario_states("demo_recon_15s")
        demo_topo = build_minimal_demo_topology()
        engine = LiveDemoEngine(topology=demo_topo, focus_node_id="svc-db")

        events = list(engine.stream_scenario(states))
        # Verify reconsideration events still fire as expected (T9..T11 reversal phase)
        recon_events = [e for e in events if e.reconsideration_triggered]
        self.assertTrue(len(recon_events) > 0)
        # Blast radius must be present simultaneously
        for re in recon_events:
            self.assertIsNotNone(re.blast_radius)
            self.assertIsNotNone(re.reconsideration)


if __name__ == "__main__":
    unittest.main()
