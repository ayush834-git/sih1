"""Topology Data Models and Boundary Contracts (SIH 26153 Task 18).

Provides first-class representations of service nodes, directed dependency edges,
criticality metadata, provenance audit trails, and explicit availability state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha256
from math import isfinite
from typing import Any, Mapping, Sequence

from core.contracts import new_id


def _score(value: float, name: str) -> None:
    if not isfinite(value) or not (0.0 <= value <= 1.0):
        raise ValueError(f"{name} must be a finite score in [0, 1], got {value}")


class ServiceType(str, Enum):
    GATEWAY = "GATEWAY"
    API = "API"
    AUTH = "AUTH"
    DATABASE = "DATABASE"
    CACHE = "CACHE"
    MESSAGE_BROKER = "MESSAGE_BROKER"
    WORKER = "WORKER"
    STORAGE = "STORAGE"
    EXTERNAL = "EXTERNAL"
    INTERNAL_SERVICE = "INTERNAL_SERVICE"
    UNKNOWN = "UNKNOWN"


class CriticalityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_score(cls, score: float) -> CriticalityLevel:
        """Derive criticality level deterministically from bounded score."""
        _score(score, "criticality score")
        if score >= 0.85:
            return cls.CRITICAL
        if score >= 0.65:
            return cls.HIGH
        if score >= 0.40:
            return cls.MEDIUM
        if score >= 0.20:
            return cls.LOW
        return cls.INFO


class DependencyType(str, Enum):
    DEPENDS_ON = "DEPENDS_ON"
    CALLS = "CALLS"
    AUTHENTICATES_WITH = "AUTHENTICATES_WITH"
    READS_FROM = "READS_FROM"
    WRITES_TO = "WRITES_TO"
    ROUTES_TO = "ROUTES_TO"
    UNKNOWN = "UNKNOWN"


class TopologyAvailability(str, Enum):
    """
    Explicit availability status of topology metadata.
    Follows Task 15 principle: 'Unavailable topology must remain unavailable.
    Never fabricate topology information.'
    """
    KNOWN = "KNOWN"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class ServiceNode:
    """
    First-class representation of an asset or service node in the enterprise dependency graph.
    """
    node_id: str
    name: str
    service_type: ServiceType
    criticality: float  # Bounded [0.0, 1.0]
    criticality_level: CriticalityLevel
    tier: str = "application"
    metadata: Mapping[str, Any] = field(default_factory=dict)
    provenance_source: str = "config"
    provenance_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.node_id or not self.name:
            raise ValueError("node_id and name are required and non-empty")
        _score(self.criticality, "criticality")
        if not self.provenance_hash:
            canonical_repr = f"{self.node_id}|{self.service_type.value}|{self.criticality:.4f}|{self.tier}|{self.provenance_source}"
            computed_hash = sha256(canonical_repr.encode("utf-8")).hexdigest()
            object.__setattr__(self, "provenance_hash", computed_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "service_type": self.service_type.value,
            "criticality": round(self.criticality, 4),
            "criticality_level": self.criticality_level.value,
            "tier": self.tier,
            "metadata": dict(self.metadata),
            "provenance_source": self.provenance_source,
            "provenance_hash": self.provenance_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServiceNode:
        return cls(
            node_id=str(data["node_id"]),
            name=str(data["name"]),
            service_type=ServiceType(data["service_type"]),
            criticality=float(data["criticality"]),
            criticality_level=CriticalityLevel(data["criticality_level"]),
            tier=str(data.get("tier", "application")),
            metadata=dict(data.get("metadata", {})),
            provenance_source=str(data.get("provenance_source", "config")),
            provenance_hash=str(data.get("provenance_hash", "")),
        )


@dataclass(frozen=True)
class DependencyEdge:
    """
    First-class directed dependency relationship between two services.
    
    Directional semantics:
        source_id -> target_id
        The source_id service DEPENDS ON target_id service.
        Example: API (source) -> Auth (target) -> Database (target)
        - get_dependencies(API) returns {Auth}
        - get_dependents(Database) returns {Auth, API}
    """
    source_id: str  # Dependent service
    target_id: str  # Dependency service
    relationship_type: DependencyType = DependencyType.DEPENDS_ON
    confidence: float = 1.0  # Bounded [0.0, 1.0]
    provenance_source: str = "config"
    provenance_hash: str = field(default="")
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source_id or not self.target_id:
            raise ValueError("source_id and target_id are required and non-empty")
        _score(self.confidence, "confidence")
        if not self.provenance_hash:
            canonical_repr = f"{self.source_id}|{self.target_id}|{self.relationship_type.value}|{self.confidence:.4f}|{self.provenance_source}"
            computed_hash = sha256(canonical_repr.encode("utf-8")).hexdigest()
            object.__setattr__(self, "provenance_hash", computed_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship_type": self.relationship_type.value,
            "confidence": round(self.confidence, 4),
            "provenance_source": self.provenance_source,
            "provenance_hash": self.provenance_hash,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DependencyEdge:
        return cls(
            source_id=str(data["source_id"]),
            target_id=str(data["target_id"]),
            relationship_type=DependencyType(data.get("relationship_type", DependencyType.DEPENDS_ON.value)),
            confidence=float(data.get("confidence", 1.0)),
            provenance_source=str(data.get("provenance_source", "config")),
            provenance_hash=str(data.get("provenance_hash", "")),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class TopologySnapshot:
    """
    An immutable audit record of a topology graph state.
    Guarantees deterministic serialization and auditable provenance.
    """
    snapshot_id: str
    availability: TopologyAvailability
    node_count: int
    edge_count: int
    nodes: tuple[ServiceNode, ...]
    edges: tuple[DependencyEdge, ...]
    provenance_source: str
    provenance_hash: str
    created_at: datetime
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "availability": self.availability.value,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "provenance_source": self.provenance_source,
            "provenance_hash": self.provenance_hash,
            "created_at": self.created_at.isoformat(),
            "notes": self.notes,
        }
