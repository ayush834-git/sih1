"""Deterministic Topology Builders (SIH 26153 Task 18).

Provides standard, auditable topology builders for demonstration, testing,
and explicit representation of unavailable network telemetry contexts.
"""
from __future__ import annotations

from core.topology.graph import ServiceTopologyGraph
from core.topology.models import (
    CriticalityLevel,
    DependencyEdge,
    DependencyType,
    ServiceNode,
    ServiceType,
    TopologyAvailability,
)


def build_minimal_demo_topology() -> ServiceTopologyGraph:
    """
    Build the canonical 3-node tier topology specified in Task 18 requirements:
        API -> Auth -> Database
        
    Semantics:
        - dependencies(API) = {Auth}
        - dependencies(Auth) = {Database}
        - dependents(Database) = {Auth, API}
    """
    graph = ServiceTopologyGraph(
        availability=TopologyAvailability.KNOWN,
        provenance_source="canonical_demo_spec",
        notes="Canonical 3-node verification topology (API -> Auth -> DB)",
    )

    api_node = ServiceNode(
        node_id="svc-api",
        name="Internet-Facing API",
        service_type=ServiceType.API,
        criticality=0.80,
        criticality_level=CriticalityLevel.HIGH,
        tier="edge",
        metadata={"public_facing": True},
        provenance_source="demo_manifest",
    )
    auth_node = ServiceNode(
        node_id="svc-auth",
        name="Authentication Service",
        service_type=ServiceType.AUTH,
        criticality=0.90,
        criticality_level=CriticalityLevel.CRITICAL,
        tier="application",
        metadata={"single_point_of_failure": True},
        provenance_source="demo_manifest",
    )
    db_node = ServiceNode(
        node_id="svc-db",
        name="Core Database",
        service_type=ServiceType.DATABASE,
        criticality=0.95,
        criticality_level=CriticalityLevel.CRITICAL,
        tier="data",
        metadata={"single_point_of_failure": True, "read_only_fallback": False},
        provenance_source="demo_manifest",
    )

    graph.add_node(api_node)
    graph.add_node(auth_node)
    graph.add_node(db_node)

    # API depends on Auth
    graph.add_dependency(
        DependencyEdge(
            source_id="svc-api",
            target_id="svc-auth",
            relationship_type=DependencyType.AUTHENTICATES_WITH,
            confidence=1.0,
            provenance_source="demo_manifest",
        )
    )
    # Auth depends on Database
    graph.add_dependency(
        DependencyEdge(
            source_id="svc-auth",
            target_id="svc-db",
            relationship_type=DependencyType.READS_FROM,
            confidence=1.0,
            provenance_source="demo_manifest",
        )
    )

    return graph


def build_enterprise_demo_topology() -> ServiceTopologyGraph:
    """
    Build a realistic 4-tier enterprise microservices dependency graph:
    Tiers:
        1. Edge: Public Ingress API Gateway
        2. Services: Auth Service, Order Processing, Payment Gateway
        3. Persistence: Customer DB, Financial Ledger DB, Session Cache, Audit Store
    """
    graph = ServiceTopologyGraph(
        availability=TopologyAvailability.KNOWN,
        provenance_source="enterprise_cmdb_manifest",
        notes="Realistic 4-tier enterprise microservice dependency graph",
    )

    nodes = [
        ServiceNode(
            node_id="svc-ingress-gw",
            name="Public Ingress API Gateway",
            service_type=ServiceType.GATEWAY,
            criticality=0.85,
            criticality_level=CriticalityLevel.CRITICAL,
            tier="edge",
            metadata={"public_ip": "203.0.113.10", "has_waf": True, "single_point_of_failure": False},
            provenance_source="cmdb",
        ),
        ServiceNode(
            node_id="svc-auth",
            name="Identity & Token Auth Service",
            service_type=ServiceType.AUTH,
            criticality=0.90,
            criticality_level=CriticalityLevel.CRITICAL,
            tier="application",
            metadata={"single_point_of_failure": True, "replicas": 3},
            provenance_source="cmdb",
        ),
        ServiceNode(
            node_id="svc-order",
            name="Order Processing Service",
            service_type=ServiceType.WORKER,
            criticality=0.75,
            criticality_level=CriticalityLevel.HIGH,
            tier="application",
            metadata={"has_replica": True, "replicas": 4},
            provenance_source="cmdb",
        ),
        ServiceNode(
            node_id="svc-payment",
            name="Payment Processing Service",
            service_type=ServiceType.API,
            criticality=0.95,
            criticality_level=CriticalityLevel.CRITICAL,
            tier="application",
            metadata={"pci_dss_in_scope": True, "single_point_of_failure": True},
            provenance_source="cmdb",
        ),
        ServiceNode(
            node_id="svc-cache",
            name="Distributed Session Cache",
            service_type=ServiceType.CACHE,
            criticality=0.60,
            criticality_level=CriticalityLevel.MEDIUM,
            tier="data",
            metadata={"in_memory": True, "cluster_nodes": 3},
            provenance_source="cmdb",
        ),
        ServiceNode(
            node_id="svc-customer-db",
            name="Customer Account Relational DB",
            service_type=ServiceType.DATABASE,
            criticality=0.92,
            criticality_level=CriticalityLevel.CRITICAL,
            tier="data",
            metadata={"single_point_of_failure": True, "encrypted_at_rest": True},
            provenance_source="cmdb",
        ),
        ServiceNode(
            node_id="svc-ledger-db",
            name="Financial Ledger ACID Database",
            service_type=ServiceType.DATABASE,
            criticality=0.98,
            criticality_level=CriticalityLevel.CRITICAL,
            tier="data",
            metadata={"single_point_of_failure": True, "immutable_log": True},
            provenance_source="cmdb",
        ),
        ServiceNode(
            node_id="svc-audit-storage",
            name="Compliance Audit Log Archive",
            service_type=ServiceType.STORAGE,
            criticality=0.70,
            criticality_level=CriticalityLevel.HIGH,
            tier="data",
            metadata={"worm_storage": True},
            provenance_source="cmdb",
        ),
    ]

    for node in nodes:
        graph.add_node(node)

    # Edge relationships: source DEPENDS ON target
    dependencies = [
        # Ingress Gateway routes to application services
        ("svc-ingress-gw", "svc-auth", DependencyType.AUTHENTICATES_WITH, 1.0),
        ("svc-ingress-gw", "svc-order", DependencyType.ROUTES_TO, 1.0),
        ("svc-ingress-gw", "svc-payment", DependencyType.ROUTES_TO, 1.0),
        # Order service depends on Auth, Cache, and Customer DB
        ("svc-order", "svc-auth", DependencyType.AUTHENTICATES_WITH, 0.95),
        ("svc-order", "svc-cache", DependencyType.READS_FROM, 0.90),
        ("svc-order", "svc-customer-db", DependencyType.READS_FROM, 1.0),
        # Payment service depends on Auth, Ledger DB, and Audit Archive
        ("svc-payment", "svc-auth", DependencyType.AUTHENTICATES_WITH, 1.0),
        ("svc-payment", "svc-ledger-db", DependencyType.WRITES_TO, 1.0),
        ("svc-payment", "svc-audit-storage", DependencyType.WRITES_TO, 0.90),
        # Auth service depends on Customer DB and Session Cache
        ("svc-auth", "svc-customer-db", DependencyType.READS_FROM, 1.0),
        ("svc-auth", "svc-cache", DependencyType.READS_FROM, 0.95),
        # Ledger DB writes transaction log to Audit storage
        ("svc-ledger-db", "svc-audit-storage", DependencyType.WRITES_TO, 0.85),
    ]

    for src, tgt, rel, conf in dependencies:
        graph.add_dependency(
            DependencyEdge(
                source_id=src,
                target_id=tgt,
                relationship_type=rel,
                confidence=conf,
                provenance_source="cmdb",
            )
        )

    return graph


def build_unavailable_topology(reason: str = "Telemetry source lacks host topology metadata") -> ServiceTopologyGraph:
    """
    Construct an explicit UNAVAILABLE topology representation.
    Guarantees that telemetry lacking host topology explicitly advertises unavailability.
    """
    return ServiceTopologyGraph.create_unavailable(reason=reason)
