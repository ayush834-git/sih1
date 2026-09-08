"""Comprehensive Test Suite for Service Topology & Dependency Graph (SIH 26153 Task 18).

Validates:
1. Basic node creation & validation
2. Basic dependency edge creation & validation
3. Directed dependency semantics (API -> Auth -> DB)
4. Direct dependencies query
5. Direct dependents query
6. Multi-hop transitive dependency traversal
7. Multi-hop transitive dependent traversal
8. Cycle handling, safety, and cycle detection
9. Duplicate node handling & idempotency
10. Duplicate edge handling & idempotency
11. Deterministic traversal ordering
12. Deterministic serialization and snapshotting
13. Criticality metadata preservation
14. Provenance preservation and SHA-256 auditability
15. Explicit unavailable and partial topology behavior (anti-fabrication)
16. Minimal DemoEvent integration & backward compatibility
17. Topology does NOT silently alter risk, priority, or response scores
18. Enterprise demo topology builder & multi-tier path chains
"""
from __future__ import annotations

import unittest
from datetime import datetime

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
    TopologySnapshot,
)
from scenarios.demo.engine import DemoEvent, LiveDemoEngine
from scenarios.demo.scenarios import get_demo_scenario_states


class TestServiceTopology(unittest.TestCase):
    """Dedicated test suite for Task 18 service topology layer."""

    def test_01_basic_node_creation(self) -> None:
        """Verify node creation, field validation, and serialization."""
        node = ServiceNode(
            node_id="svc-auth",
            name="Authentication Service",
            service_type=ServiceType.AUTH,
            criticality=0.90,
            criticality_level=CriticalityLevel.CRITICAL,
            tier="application",
            metadata={"single_point_of_failure": True},
            provenance_source="test_manifest",
        )
        self.assertEqual(node.node_id, "svc-auth")
        self.assertEqual(node.name, "Authentication Service")
        self.assertEqual(node.service_type, ServiceType.AUTH)
        self.assertEqual(node.criticality, 0.90)
        self.assertEqual(node.criticality_level, CriticalityLevel.CRITICAL)
        self.assertEqual(node.tier, "application")
        self.assertTrue(node.metadata["single_point_of_failure"])
        self.assertEqual(len(node.provenance_hash), 64)

        # Serialization roundtrip
        d = node.to_dict()
        self.assertEqual(d["node_id"], "svc-auth")
        self.assertEqual(d["criticality"], 0.90)
        restored = ServiceNode.from_dict(d)
        self.assertEqual(restored, node)

        # Validation: criticality out of range
        with self.assertRaises(ValueError):
            ServiceNode(
                node_id="svc-bad",
                name="Bad",
                service_type=ServiceType.API,
                criticality=1.5,
                criticality_level=CriticalityLevel.CRITICAL,
            )

        # Validation: empty ID
        with self.assertRaises(ValueError):
            ServiceNode(
                node_id="",
                name="Empty ID",
                service_type=ServiceType.API,
                criticality=0.5,
                criticality_level=CriticalityLevel.MEDIUM,
            )

    def test_02_basic_dependency_edge_creation(self) -> None:
        """Verify dependency edge creation, field validation, and serialization."""
        edge = DependencyEdge(
            source_id="svc-api",
            target_id="svc-auth",
            relationship_type=DependencyType.AUTHENTICATES_WITH,
            confidence=0.95,
            provenance_source="test_manifest",
            metadata={"protocol": "gRPC"},
        )
        self.assertEqual(edge.source_id, "svc-api")
        self.assertEqual(edge.target_id, "svc-auth")
        self.assertEqual(edge.relationship_type, DependencyType.AUTHENTICATES_WITH)
        self.assertEqual(edge.confidence, 0.95)
        self.assertEqual(len(edge.provenance_hash), 64)

        # Serialization roundtrip
        d = edge.to_dict()
        self.assertEqual(d["source_id"], "svc-api")
        self.assertEqual(d["target_id"], "svc-auth")
        restored = DependencyEdge.from_dict(d)
        self.assertEqual(restored, edge)

        # Validation: invalid confidence
        with self.assertRaises(ValueError):
            DependencyEdge(source_id="a", target_id="b", confidence=-0.1)

    def test_03_directed_dependency_semantics(self) -> None:
        """Verify directed dependency semantics: API -> Auth -> DB."""
        graph = build_minimal_demo_topology()
        self.assertEqual(graph.node_count, 3)
        self.assertEqual(graph.edge_count, 2)

        # Edge direction: source depends on target
        self.assertTrue(graph.has_node("svc-api"))
        self.assertTrue(graph.has_node("svc-auth"))
        self.assertTrue(graph.has_node("svc-db"))

    def test_04_direct_dependencies(self) -> None:
        """Verify direct dependencies (outgoing edges: what does X depend on?)."""
        graph = build_minimal_demo_topology()
        # API depends directly on Auth
        self.assertEqual(graph.get_dependencies("svc-api"), ["svc-auth"])
        # Auth depends directly on Database
        self.assertEqual(graph.get_dependencies("svc-auth"), ["svc-db"])
        # Database depends on nothing
        self.assertEqual(graph.get_dependencies("svc-db"), [])
        # Nonexistent node
        self.assertEqual(graph.get_dependencies("nonexistent"), [])

    def test_05_direct_dependents(self) -> None:
        """Verify direct dependents (incoming edges: what depends on X?)."""
        graph = build_minimal_demo_topology()
        # Database is directly depended upon by Auth
        self.assertEqual(graph.get_dependents("svc-db"), ["svc-auth"])
        # Auth is directly depended upon by API
        self.assertEqual(graph.get_dependents("svc-auth"), ["svc-api"])
        # API has no dependents
        self.assertEqual(graph.get_dependents("svc-api"), [])
        # Nonexistent node
        self.assertEqual(graph.get_dependents("nonexistent"), [])

    def test_06_multi_hop_dependency_traversal(self) -> None:
        """Verify multi-hop upstream dependency traversal."""
        graph = build_minimal_demo_topology()
        # API transitively depends on Auth, then Database
        api_transitive = graph.get_transitive_dependencies("svc-api")
        self.assertEqual(api_transitive, ["svc-auth", "svc-db"])

        # Auth transitively depends only on Database
        auth_transitive = graph.get_transitive_dependencies("svc-auth")
        self.assertEqual(auth_transitive, ["svc-db"])

        # Database has no transitive dependencies
        db_transitive = graph.get_transitive_dependencies("svc-db")
        self.assertEqual(db_transitive, [])

    def test_07_multi_hop_dependent_traversal(self) -> None:
        """Verify multi-hop downstream dependent traversal."""
        graph = build_minimal_demo_topology()
        # Database has downstream dependents: Auth (direct), API (transitive)
        db_dependents = graph.get_transitive_dependents("svc-db")
        self.assertEqual(db_dependents, ["svc-auth", "svc-api"])

        # Auth has downstream dependent: API
        auth_dependents = graph.get_transitive_dependents("svc-auth")
        self.assertEqual(auth_dependents, ["svc-api"])

        # API has no downstream dependents
        api_dependents = graph.get_transitive_dependents("svc-api")
        self.assertEqual(api_dependents, [])

    def test_08_cycle_handling_termination_and_detection(self) -> None:
        """Verify cycle detection and safe traversal termination on cyclic graphs."""
        graph = ServiceTopologyGraph(notes="Cyclic graph test")
        for node_id in ["node-a", "node-b", "node-c"]:
            graph.add_node(
                ServiceNode(
                    node_id=node_id,
                    name=f"Node {node_id}",
                    service_type=ServiceType.INTERNAL_SERVICE,
                    criticality=0.5,
                    criticality_level=CriticalityLevel.MEDIUM,
                )
            )

        # Create cycle: A -> B -> C -> A
        graph.add_dependency(DependencyEdge(source_id="node-a", target_id="node-b"))
        graph.add_dependency(DependencyEdge(source_id="node-b", target_id="node-c"))
        graph.add_dependency(DependencyEdge(source_id="node-c", target_id="node-a"))

        # Cycle detection
        self.assertTrue(graph.has_cycle())
        cycles = graph.find_cycles()
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0], ["node-a", "node-b", "node-c", "node-a"])

        # Traversal MUST terminate safely without infinite recursion or duplicates
        deps_a = graph.get_transitive_dependencies("node-a")
        self.assertEqual(deps_a, ["node-b", "node-c"])

        dependents_c = graph.get_transitive_dependents("node-c")
        self.assertEqual(dependents_c, ["node-b", "node-a"])

    def test_09_duplicate_node_handling_idempotency(self) -> None:
        """Verify adding identical or updated nodes is idempotent."""
        graph = ServiceTopologyGraph()
        node1 = ServiceNode(
            node_id="svc-1",
            name="Service One",
            service_type=ServiceType.API,
            criticality=0.5,
            criticality_level=CriticalityLevel.MEDIUM,
        )
        graph.add_node(node1)
        self.assertEqual(graph.node_count, 1)

        # Duplicate addition
        graph.add_node(node1)
        self.assertEqual(graph.node_count, 1)

        # Update node metadata with same ID
        node1_updated = ServiceNode(
            node_id="svc-1",
            name="Service One Updated",
            service_type=ServiceType.API,
            criticality=0.8,
            criticality_level=CriticalityLevel.HIGH,
        )
        graph.add_node(node1_updated)
        self.assertEqual(graph.node_count, 1)
        self.assertEqual(graph.get_node("svc-1").name, "Service One Updated")
        self.assertEqual(graph.get_node("svc-1").criticality, 0.8)

    def test_10_duplicate_edge_handling_idempotency(self) -> None:
        """Verify adding identical dependency edge multiple times is idempotent."""
        graph = ServiceTopologyGraph()
        graph.add_node(ServiceNode("a", "Node A", ServiceType.API, 0.5, CriticalityLevel.MEDIUM))
        graph.add_node(ServiceNode("b", "Node B", ServiceType.DATABASE, 0.5, CriticalityLevel.MEDIUM))

        edge = DependencyEdge("a", "b", DependencyType.DEPENDS_ON, confidence=0.9)
        graph.add_dependency(edge)
        self.assertEqual(graph.edge_count, 1)

        # Duplicate addition
        graph.add_dependency(edge)
        self.assertEqual(graph.edge_count, 1)

        # Addition with helper method
        graph.add_dependency("a", "b", DependencyType.DEPENDS_ON, confidence=0.95)
        self.assertEqual(graph.edge_count, 1)

    def test_11_deterministic_traversal_ordering(self) -> None:
        """Verify that traversal order is deterministic across runs regardless of branch count."""
        graph = ServiceTopologyGraph()
        root = ServiceNode("root", "Root", ServiceType.GATEWAY, 0.5, CriticalityLevel.MEDIUM)
        graph.add_node(root)

        # Add children in arbitrary/non-alphabetical order
        child_ids = ["svc-z", "svc-a", "svc-m", "svc-b", "svc-x"]
        for cid in child_ids:
            graph.add_node(ServiceNode(cid, cid, ServiceType.INTERNAL_SERVICE, 0.5, CriticalityLevel.MEDIUM))
            graph.add_dependency("root", cid)

        # Direct dependencies must be sorted lexicographically
        self.assertEqual(graph.get_dependencies("root"), ["svc-a", "svc-b", "svc-m", "svc-x", "svc-z"])

        # Transitive dependencies must also be deterministic
        for _ in range(5):
            self.assertEqual(
                graph.get_transitive_dependencies("root"),
                ["svc-a", "svc-b", "svc-m", "svc-x", "svc-z"],
            )

    def test_12_deterministic_serialization(self) -> None:
        """Verify deterministic serialization and snapshot output regardless of insertion order."""
        # Graph 1: inserted in order A, B, C
        g1 = ServiceTopologyGraph()
        for nid in ["a", "b", "c"]:
            g1.add_node(ServiceNode(nid, f"Node {nid}", ServiceType.API, 0.5, CriticalityLevel.MEDIUM))
        g1.add_dependency("a", "b")
        g1.add_dependency("b", "c")

        # Graph 2: inserted in order C, A, B
        g2 = ServiceTopologyGraph()
        for nid in ["c", "a", "b"]:
            g2.add_node(ServiceNode(nid, f"Node {nid}", ServiceType.API, 0.5, CriticalityLevel.MEDIUM))
        g2.add_dependency("b", "c")
        g2.add_dependency("a", "b")

        d1 = g1.to_dict()
        d2 = g2.to_dict()

        self.assertEqual(d1["nodes"], d2["nodes"])
        self.assertEqual(d1["edges"], d2["edges"])

        # Snapshots have identical content hashes
        snap1 = g1.to_snapshot("fixed-id")
        snap2 = g2.to_snapshot("fixed-id")
        self.assertEqual(snap1.provenance_hash, snap2.provenance_hash)

    def test_13_criticality_metadata_preservation(self) -> None:
        """Verify criticality score and level are preserved with arbitrary metadata."""
        node = ServiceNode(
            node_id="svc-db-critical",
            name="Primary DB",
            service_type=ServiceType.DATABASE,
            criticality=0.98,
            criticality_level=CriticalityLevel.CRITICAL,
            tier="data",
            metadata={"read_only_fallback": False, "rpo_minutes": 0, "rto_minutes": 5},
        )
        self.assertEqual(node.criticality, 0.98)
        self.assertEqual(node.criticality_level, CriticalityLevel.CRITICAL)
        self.assertFalse(node.metadata["read_only_fallback"])
        self.assertEqual(node.metadata["rpo_minutes"], 0)

        # Automatic level derivation test
        self.assertEqual(CriticalityLevel.from_score(0.95), CriticalityLevel.CRITICAL)
        self.assertEqual(CriticalityLevel.from_score(0.70), CriticalityLevel.HIGH)
        self.assertEqual(CriticalityLevel.from_score(0.50), CriticalityLevel.MEDIUM)
        self.assertEqual(CriticalityLevel.from_score(0.25), CriticalityLevel.LOW)
        self.assertEqual(CriticalityLevel.from_score(0.10), CriticalityLevel.INFO)

    def test_14_provenance_preservation(self) -> None:
        """Verify provenance source and SHA-256 hash auditability."""
        node = ServiceNode(
            node_id="svc-test",
            name="Test",
            service_type=ServiceType.API,
            criticality=0.5,
            criticality_level=CriticalityLevel.MEDIUM,
            provenance_source="verified_cmdb_feed",
        )
        self.assertEqual(node.provenance_source, "verified_cmdb_feed")
        self.assertEqual(len(node.provenance_hash), 64)

        # Altering node attributes alters hash
        node_diff = ServiceNode(
            node_id="svc-test",
            name="Test",
            service_type=ServiceType.API,
            criticality=0.9,
            criticality_level=CriticalityLevel.CRITICAL,
            provenance_source="verified_cmdb_feed",
        )
        self.assertNotEqual(node.provenance_hash, node_diff.provenance_hash)

    def test_15_explicit_unavailable_and_partial_topology(self) -> None:
        """Verify explicit UNAVAILABLE and PARTIAL topology representation (anti-fabrication)."""
        unavail = build_unavailable_topology("NetFlow CSV source lacks host topology telemetry")
        self.assertEqual(unavail.availability, TopologyAvailability.UNAVAILABLE)
        self.assertEqual(unavail.node_count, 0)
        self.assertEqual(unavail.edge_count, 0)
        self.assertIn("NetFlow CSV source", unavail.notes)

        # Partial topology
        partial = ServiceTopologyGraph.create_partial(
            nodes=[ServiceNode("a", "A", ServiceType.API, 0.5, CriticalityLevel.MEDIUM)],
            edges=[],
            reason="Observed partial connection from packet inspection",
        )
        self.assertEqual(partial.availability, TopologyAvailability.PARTIAL)
        self.assertEqual(partial.node_count, 1)

    def test_16_demo_event_integration_backward_compatibility(self) -> None:
        """Verify DemoEvent backwards compatibility and topology_context integration."""
        states = get_demo_scenario_states("demo_recon_15s")[:3]
        demo_topo = build_minimal_demo_topology()

        # Engine with topology attached
        engine_with_topo = LiveDemoEngine(topology=demo_topo)
        events_with_topo = list(engine_with_topo.stream_scenario(states))
        self.assertEqual(len(events_with_topo), 3)

        first_evt = events_with_topo[0]
        self.assertIsNotNone(first_evt.topology_context)
        self.assertEqual(first_evt.topology_context["availability"], "KNOWN")
        self.assertEqual(first_evt.topology_context["node_count"], 3)
        self.assertEqual(first_evt.topology_context["edge_count"], 2)

        # Engine without topology (backward compatibility)
        engine_no_topo = LiveDemoEngine(topology=None)
        events_no_topo = list(engine_no_topo.stream_scenario(states))
        self.assertEqual(len(events_no_topo), 3)
        self.assertIsNone(events_no_topo[0].topology_context)

    def test_17_topology_does_not_silently_alter_risk_or_priority(self) -> None:
        """CRITICAL INVARIANT: Topology MUST NOT silently alter risk, priority, or response scores."""
        states = get_demo_scenario_states("demo_recon_15s")[:10]
        demo_topo = build_enterprise_demo_topology()

        engine_baseline = LiveDemoEngine(topology=None)
        engine_with_topo = LiveDemoEngine(topology=demo_topo)

        events_baseline = list(engine_baseline.stream_scenario(states))
        events_with_topo = list(engine_with_topo.stream_scenario(states))

        for idx, (b_evt, t_evt) in enumerate(zip(events_baseline, events_with_topo)):
            # Risk scores must be identical
            self.assertAlmostEqual(b_evt.current_risk_score, t_evt.current_risk_score, places=5)
            self.assertEqual(b_evt.future_risk_scores, t_evt.future_risk_scores)
            
            # Priority must be identical
            self.assertEqual(b_evt.priority_level, t_evt.priority_level)
            self.assertAlmostEqual(b_evt.composite_priority, t_evt.composite_priority, places=5)
            
            # Strategy and actions must be identical
            self.assertEqual(b_evt.recommended_strategy, t_evt.recommended_strategy)
            self.assertEqual(b_evt.recommended_actions, t_evt.recommended_actions)

            # Hypotheses and trust must be identical
            self.assertEqual(b_evt.primary_stage, t_evt.primary_stage)
            self.assertAlmostEqual(b_evt.composite_trust, t_evt.composite_trust, places=5)

    def test_18_enterprise_topology_builder_and_chains(self) -> None:
        """Verify enterprise demo topology builder, 4 tiers, and multi-hop dependency chains."""
        graph = build_enterprise_demo_topology()
        self.assertEqual(graph.node_count, 8)
        self.assertEqual(graph.edge_count, 12)
        self.assertFalse(graph.has_cycle())

        # Path finding: chain from Ingress Gateway to Customer DB
        chains_to_db = graph.get_dependency_chain("svc-ingress-gw", "svc-customer-db")
        self.assertTrue(len(chains_to_db) >= 2)
        # Expected paths:
        # [svc-ingress-gw -> svc-auth -> svc-customer-db]
        # [svc-ingress-gw -> svc-order -> svc-customer-db]
        self.assertIn(["svc-ingress-gw", "svc-auth", "svc-customer-db"], chains_to_db)
        self.assertIn(["svc-ingress-gw", "svc-order", "svc-customer-db"], chains_to_db)

        # Transitive dependents of customer DB: who breaks if Customer DB fails?
        # (Structural traversal only — no blast radius calculation)
        db_dependents = graph.get_transitive_dependents("svc-customer-db")
        self.assertIn("svc-auth", db_dependents)
        self.assertIn("svc-order", db_dependents)
        self.assertIn("svc-ingress-gw", db_dependents)


if __name__ == "__main__":
    unittest.main()
