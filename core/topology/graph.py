"""Service Topology Graph & Traversal Engine (SIH 26153 Task 18).

Provides directed dependency graph storage, cycle-safe multi-hop traversal,
deterministic serialization, audit provenance, and explicit availability status.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime
from hashlib import sha256
from typing import Any, Mapping, Sequence

from core.contracts import new_id
from core.topology.models import (
    CriticalityLevel,
    DependencyEdge,
    DependencyType,
    ServiceNode,
    ServiceType,
    TopologyAvailability,
    TopologySnapshot,
)


class ServiceTopologyGraph:
    """
    First-class directed graph representing service/asset dependencies.

    Directional semantics:
        Edge(source=A, target=B) means A DEPENDS ON B.
        - Outgoing edges from A point to services A depends on (A's dependencies).
        - Incoming edges to B come from services that depend on B (B's dependents).

    Guarantees:
        - Termination on cycles (no infinite recursion).
        - Idempotency for duplicate nodes and edges.
        - Deterministic traversal and serialization ordering.
        - Explicit KNOWN / PARTIAL / UNAVAILABLE availability semantics.
        - Zero blast-radius or risk calculation (strictly deferred to Task 19).
    """

    def __init__(
        self,
        availability: TopologyAvailability = TopologyAvailability.KNOWN,
        provenance_source: str = "config",
        notes: str | None = None,
        snapshot_id: str | None = None,
    ) -> None:
        self.availability = availability
        self.provenance_source = provenance_source
        self.notes = notes
        self.snapshot_id = snapshot_id
        
        # Internal node store: node_id -> ServiceNode
        self._nodes: dict[str, ServiceNode] = {}
        
        # Outgoing edges: source_id -> dict[(target_id, relationship_type), DependencyEdge]
        # Represents: source_id DEPENDS ON target_id
        self._out_edges: dict[str, dict[tuple[str, DependencyType], DependencyEdge]] = {}
        
        # Incoming edges: target_id -> dict[(source_id, relationship_type), DependencyEdge]
        # Represents: source_id DEPENDS ON target_id (so source_id is a dependent of target_id)
        self._in_edges: dict[str, dict[tuple[str, DependencyType], DependencyEdge]] = {}

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(edges) for edges in self._out_edges.values())

    def add_node(self, node: ServiceNode) -> None:
        """
        Add a service node to the topology. Idempotent.
        If node_id already exists with identical data, no-op.
        If attributes differ, updates node in place while maintaining validity.
        """
        if not isinstance(node, ServiceNode):
            raise TypeError(f"Expected ServiceNode, got {type(node).__name__}")

        self._nodes[node.node_id] = node
        if node.node_id not in self._out_edges:
            self._out_edges[node.node_id] = {}
        if node.node_id not in self._in_edges:
            self._in_edges[node.node_id] = {}

    def get_node(self, node_id: str) -> ServiceNode | None:
        """Retrieve node by ID or return None if not present."""
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        """Check if a node ID exists in the topology."""
        return node_id in self._nodes

    def get_all_nodes(self) -> list[ServiceNode]:
        """Return all nodes sorted deterministically by node_id."""
        return [self._nodes[k] for k in sorted(self._nodes.keys())]

    def add_dependency(
        self,
        edge_or_source: DependencyEdge | str,
        target_id: str | None = None,
        relationship_type: DependencyType = DependencyType.DEPENDS_ON,
        confidence: float = 1.0,
        provenance_source: str = "config",
        metadata: Mapping[str, Any] | None = None,
    ) -> DependencyEdge:
        """
        Add a directed dependency edge: source_id DEPENDS ON target_id.
        Idempotent: Duplicate additions update/preserve edge without duplication.
        
        Raises ValueError if either source or target node is not registered.
        """
        if isinstance(edge_or_source, DependencyEdge):
            edge = edge_or_source
        else:
            if target_id is None:
                raise ValueError("target_id is required when adding dependency by string ID")
            edge = DependencyEdge(
                source_id=edge_or_source,
                target_id=target_id,
                relationship_type=relationship_type,
                confidence=confidence,
                provenance_source=provenance_source,
                metadata=dict(metadata or {}),
            )

        if edge.source_id not in self._nodes:
            raise ValueError(f"Cannot add dependency: source node '{edge.source_id}' does not exist")
        if edge.target_id not in self._nodes:
            raise ValueError(f"Cannot add dependency: target node '{edge.target_id}' does not exist")

        key = (edge.target_id, edge.relationship_type)
        self._out_edges[edge.source_id][key] = edge

        in_key = (edge.source_id, edge.relationship_type)
        self._in_edges[edge.target_id][in_key] = edge

        return edge

    def get_dependencies(self, node_id: str) -> list[str]:
        """
        Return direct upstream dependencies that node_id depends on.
        Example: API -> Auth -> Database
        get_dependencies(API) returns ["Auth"].
        Deterministic: Sorted lexicographically.
        """
        if node_id not in self._out_edges:
            return []
        targets = {edge.target_id for edge in self._out_edges[node_id].values()}
        return sorted(targets)

    def get_dependents(self, node_id: str) -> list[str]:
        """
        Return direct downstream dependents that depend on node_id.
        Example: API -> Auth -> Database
        get_dependents(Database) returns ["Auth"].
        Deterministic: Sorted lexicographically.
        """
        if node_id not in self._in_edges:
            return []
        sources = {edge.source_id for edge in self._in_edges[node_id].values()}
        return sorted(sources)

    def get_transitive_dependencies(self, node_id: str) -> list[str]:
        """
        Return all upstream dependencies reachable from node_id (multi-hop).
        Follows outgoing edges: node_id -> ... -> upstream.
        Example: API -> Auth -> Database
        get_transitive_dependencies(API) returns ["Auth", "Database"].
        
        Guarantees:
        - Safe termination on cycles.
        - No duplicates.
        - Deterministic BFS level-order with lexicographical tie-breaking.
        """
        if node_id not in self._nodes:
            return []

        visited: set[str] = set()
        queue: deque[str] = deque([node_id])
        result: list[str] = []

        while queue:
            current = queue.popleft()
            # Sorted direct dependencies for deterministic expansion
            direct = self.get_dependencies(current)
            for dep in direct:
                if dep not in visited and dep != node_id:
                    visited.add(dep)
                    result.append(dep)
                    queue.append(dep)

        return result

    def get_transitive_dependents(self, node_id: str) -> list[str]:
        """
        Return all downstream dependents that transitively depend on node_id (multi-hop).
        Follows incoming edges: downstream -> ... -> node_id.
        Example: API -> Auth -> Database
        get_transitive_dependents(Database) returns ["API", "Auth"] (in deterministic order).
        
        Guarantees:
        - Safe termination on cycles.
        - No duplicates.
        - Deterministic BFS level-order with lexicographical tie-breaking.
        """
        if node_id not in self._nodes:
            return []

        visited: set[str] = set()
        queue: deque[str] = deque([node_id])
        result: list[str] = []

        while queue:
            current = queue.popleft()
            # Sorted direct dependents for deterministic expansion
            direct = self.get_dependents(current)
            for dep in direct:
                if dep not in visited and dep != node_id:
                    visited.add(dep)
                    result.append(dep)
                    queue.append(dep)

        return result

    def get_dependency_chain(self, source_id: str, target_id: str) -> list[list[str]]:
        """
        Find all acyclic dependency paths from source_id to target_id.
        Example: API -> Auth -> Database returns [["API", "Auth", "Database"]].
        Returns empty list if no path exists or either node is missing.
        Deterministic: Paths are sorted lexicographically.
        """
        if source_id not in self._nodes or target_id not in self._nodes:
            return []
        if source_id == target_id:
            return [[source_id]]

        paths: list[list[str]] = []

        def dfs(curr: str, target: str, current_path: list[str], visited_in_path: set[str]) -> None:
            if curr == target:
                paths.append(list(current_path))
                return
            for neighbor in self.get_dependencies(curr):
                if neighbor not in visited_in_path:
                    visited_in_path.add(neighbor)
                    current_path.append(neighbor)
                    dfs(neighbor, target, current_path, visited_in_path)
                    current_path.pop()
                    visited_in_path.remove(neighbor)

        dfs(source_id, target_id, [source_id], {source_id})
        paths.sort()
        return paths

    def has_cycle(self) -> bool:
        """
        Check if the graph contains any directed cycle.
        Returns True if a cycle exists, False otherwise.
        """
        # States: 0 = unvisited, 1 = visiting (recursion stack), 2 = visited
        state: dict[str, int] = {k: 0 for k in self._nodes}

        def dfs(u: str) -> bool:
            state[u] = 1
            for v in self.get_dependencies(u):
                if state.get(v, 0) == 1:
                    return True
                if state.get(v, 0) == 0:
                    if dfs(v):
                        return True
            state[u] = 2
            return False

        for node_id in sorted(self._nodes.keys()):
            if state[node_id] == 0:
                if dfs(node_id):
                    return True
        return False

    def find_cycles(self) -> list[list[str]]:
        """
        Find elementary directed cycles in the graph deterministically.
        Returns list of cycle path lists, e.g. [["A", "B", "C", "A"]].
        """
        cycles: list[list[str]] = []
        visited: set[str] = set()

        def dfs(start_node: str, current_node: str, path: list[str], path_set: set[str]) -> None:
            for neighbor in self.get_dependencies(current_node):
                if neighbor == start_node and len(path) >= 2:
                    cycle = list(path) + [start_node]
                    cycles.append(cycle)
                elif neighbor not in path_set and neighbor not in visited:
                    path.append(neighbor)
                    path_set.add(neighbor)
                    dfs(start_node, neighbor, path, path_set)
                    path.pop()
                    path_set.remove(neighbor)

        for node_id in sorted(self._nodes.keys()):
            visited.add(node_id)
            dfs(node_id, node_id, [node_id], {node_id})

        # Normalize cycles so cycle starting representation is canonical
        normalized_cycles: list[list[str]] = []
        seen_sets: set[tuple[str, ...]] = set()

        for c in cycles:
            body = c[:-1]
            min_node = min(body)
            min_idx = body.index(min_node)
            rotated = tuple(body[min_idx:] + body[:min_idx])
            if rotated not in seen_sets:
                seen_sets.add(rotated)
                normalized_cycles.append(list(rotated) + [rotated[0]])

        normalized_cycles.sort()
        return normalized_cycles

    def get_all_edges(self) -> list[DependencyEdge]:
        """Return all edges sorted deterministically by (source_id, target_id, relationship_type)."""
        edges: list[DependencyEdge] = []
        for src in sorted(self._out_edges.keys()):
            for k in sorted(self._out_edges[src].keys(), key=lambda item: (item[0], item[1].value)):
                edges.append(self._out_edges[src][k])
        return edges

    def to_snapshot(self, snapshot_id: str | None = None) -> TopologySnapshot:
        """
        Produce an immutable, deterministically ordered snapshot of the graph.
        """
        s_id = snapshot_id or self.snapshot_id or new_id("toposnap")
        self.snapshot_id = s_id
        nodes = tuple(self.get_all_nodes())
        edges = tuple(self.get_all_edges())
        
        # Deterministic provenance hash over canonical graph content
        content_repr = f"{self.availability.value}|{len(nodes)}|{len(edges)}|" + "|".join(
            f"{n.node_id}:{n.criticality:.4f}" for n in nodes
        ) + "|" + "|".join(
            f"{e.source_id}->{e.target_id}:{e.relationship_type.value}" for e in edges
        )
        prov_hash = sha256(content_repr.encode("utf-8")).hexdigest()

        return TopologySnapshot(
            snapshot_id=s_id,
            availability=self.availability,
            node_count=len(nodes),
            edge_count=len(edges),
            nodes=nodes,
            edges=edges,
            provenance_source=self.provenance_source,
            provenance_hash=prov_hash,
            created_at=datetime.now(),
            notes=self.notes,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Produce a deterministic JSON-serializable dictionary representation.
        Nodes and edges are always sorted canonically.
        """
        nodes_list = [n.to_dict() for n in self.get_all_nodes()]
        edges_list = [e.to_dict() for e in self.get_all_edges()]
        return {
            "availability": self.availability.value,
            "provenance_source": self.provenance_source,
            "node_count": len(nodes_list),
            "edge_count": len(edges_list),
            "nodes": nodes_list,
            "edges": edges_list,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServiceTopologyGraph:
        """Construct a ServiceTopologyGraph from a serialized dictionary."""
        graph = cls(
            availability=TopologyAvailability(data["availability"]),
            provenance_source=str(data.get("provenance_source", "config")),
            notes=data.get("notes"),
        )
        for n_data in data.get("nodes", []):
            graph.add_node(ServiceNode.from_dict(n_data))
        for e_data in data.get("edges", []):
            graph.add_dependency(DependencyEdge.from_dict(e_data))
        return graph

    @classmethod
    def create_unavailable(cls, reason: str = "Telemetry source lacks host topology metadata") -> ServiceTopologyGraph:
        """
        Factory to create an explicitly UNAVAILABLE topology representation.
        Follows the anti-fabrication mandate: Never fabricate topology if missing.
        """
        return cls(
            availability=TopologyAvailability.UNAVAILABLE,
            provenance_source="unavailable_telemetry",
            notes=reason,
        )

    @classmethod
    def create_partial(
        cls,
        nodes: Sequence[ServiceNode],
        edges: Sequence[DependencyEdge],
        reason: str = "Partial topology observed from flow telemetry",
    ) -> ServiceTopologyGraph:
        """
        Factory to create an explicitly PARTIAL topology representation.
        """
        graph = cls(
            availability=TopologyAvailability.PARTIAL,
            provenance_source="partial_telemetry",
            notes=reason,
        )
        for node in nodes:
            graph.add_node(node)
        for edge in edges:
            graph.add_dependency(edge)
        return graph
