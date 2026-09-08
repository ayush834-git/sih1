"""Blast Radius & Impact Analysis Contracts (SIH 26153 Task 19).

Provides first-class representations of structural blast-radius assessments,
dependency impact depths, criticality heuristics, and explicit availability status.

CRITICAL INVARIANT:
This model represents structural dependency exposure, NOT attack-propagation probability
or economic loss.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha256
from math import isfinite
from typing import Any, Mapping, Sequence

from core.topology.models import CriticalityLevel, TopologyAvailability


def _score(value: float, name: str) -> None:
    if not isfinite(value) or not (0.0 <= value <= 1.0):
        raise ValueError(f"{name} must be a finite score in [0, 1], got {value}")


class BlastRadiusStatus(str, Enum):
    """
    Explicit status of a structural blast-radius evaluation.
    Distinguishes complete analysis from partial visibility, unavailable topology,
    or missing root nodes.
    """
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    ROOT_NOT_FOUND = "ROOT_NOT_FOUND"


@dataclass(frozen=True)
class BlastRadiusAssessment:
    """
    Immutable audit record of a structural blast-radius assessment for an affected root service.

    Attributes:
        assessment_id: Unique assessment identifier.
        root_node_id: The target service/asset evaluated as the focus of the event.
        topology_snapshot_id: Snapshot ID of the evaluated topology graph.
        topology_availability: Topology availability at time of evaluation (KNOWN, PARTIAL, UNAVAILABLE).
        status: Analysis status (COMPLETE, PARTIAL, UNAVAILABLE, ROOT_NOT_FOUND).
        direct_dependent_ids: Services that directly depend on the root node (depth 1).
        transitive_dependent_ids: All downstream services reachable from the root (depth >= 1).
        affected_node_ids: Total downstream dependent nodes exposed (equals transitive_dependent_ids).
        affected_node_count: Number of downstream dependent nodes (strictly excludes root).
        node_depths: Shortest dependency path distance from root (depth 1, 2, ...).
        maximum_dependency_depth: Maximum dependency depth observed across all affected nodes.
        critical_affected_node_ids: Affected nodes with CriticalityLevel.CRITICAL.
        high_criticality_affected_node_ids: Affected nodes with CriticalityLevel.HIGH.
        weighted_impact_score: Transparent structural impact heuristic in [0.0, 1.0].
        coverage_ratio: Measurable topology coverage ratio in [0.0, 1.0], or None if indeterminate.
        is_complete: True strictly when topology is KNOWN and root was resolved.
        explanation: Human-readable audit narrative detailing structural exposure and caveats.
        provenance_hash: Canonical SHA-256 integrity hash.
        created_at: Assessment creation timestamp.
    """
    assessment_id: str
    root_node_id: str
    topology_snapshot_id: str
    topology_availability: TopologyAvailability
    status: BlastRadiusStatus
    direct_dependent_ids: tuple[str, ...]
    transitive_dependent_ids: tuple[str, ...]
    affected_node_ids: tuple[str, ...]
    affected_node_count: int
    node_depths: Mapping[str, int] = field(default_factory=dict)
    maximum_dependency_depth: int = 0
    critical_affected_node_ids: tuple[str, ...] = field(default_factory=tuple)
    high_criticality_affected_node_ids: tuple[str, ...] = field(default_factory=tuple)
    weighted_impact_score: float = 0.0
    coverage_ratio: float | None = None
    is_complete: bool = False
    explanation: str = ""
    provenance_hash: str = field(default="")
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self) -> None:
        if not self.assessment_id:
            raise ValueError("assessment_id is required")
        if not self.root_node_id:
            raise ValueError("root_node_id is required")
        _score(self.weighted_impact_score, "weighted_impact_score")
        if self.coverage_ratio is not None:
            _score(self.coverage_ratio, "coverage_ratio")
        if self.affected_node_count != len(self.affected_node_ids):
            raise ValueError("affected_node_count must equal len(affected_node_ids)")
        if self.root_node_id in self.affected_node_ids:
            raise ValueError(f"Root node '{self.root_node_id}' cannot be an affected dependent of itself")

        # Deterministic SHA-256 provenance hash over canonical evaluation content
        if not self.provenance_hash:
            cov_str = f"{self.coverage_ratio:.4f}" if self.coverage_ratio is not None else "INDETERMINATE"
            canonical_repr = (
                f"{self.root_node_id}|{self.topology_snapshot_id}|"
                f"{self.status.value}|{self.affected_node_count}|{self.maximum_dependency_depth}|"
                f"{self.weighted_impact_score:.4f}|{cov_str}|"
                f"{','.join(self.affected_node_ids)}"
            )
            object.__setattr__(self, "provenance_hash", sha256(canonical_repr.encode("utf-8")).hexdigest())

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "root_node_id": self.root_node_id,
            "topology_snapshot_id": self.topology_snapshot_id,
            "topology_availability": self.topology_availability.value,
            "status": self.status.value,
            "direct_dependent_ids": list(self.direct_dependent_ids),
            "transitive_dependent_ids": list(self.transitive_dependent_ids),
            "affected_node_ids": list(self.affected_node_ids),
            "affected_node_count": self.affected_node_count,
            "node_depths": dict(self.node_depths),
            "maximum_dependency_depth": self.maximum_dependency_depth,
            "critical_affected_node_ids": list(self.critical_affected_node_ids),
            "high_criticality_affected_node_ids": list(self.high_criticality_affected_node_ids),
            "weighted_impact_score": round(self.weighted_impact_score, 4),
            "coverage_ratio": round(self.coverage_ratio, 4) if self.coverage_ratio is not None else None,
            "is_complete": self.is_complete,
            "explanation": self.explanation,
            "provenance_hash": self.provenance_hash,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BlastRadiusAssessment:
        cov = data.get("coverage_ratio")
        return cls(
            assessment_id=str(data["assessment_id"]),
            root_node_id=str(data["root_node_id"]),
            topology_snapshot_id=str(data["topology_snapshot_id"]),
            topology_availability=TopologyAvailability(data["topology_availability"]),
            status=BlastRadiusStatus(data["status"]),
            direct_dependent_ids=tuple(data.get("direct_dependent_ids", [])),
            transitive_dependent_ids=tuple(data.get("transitive_dependent_ids", [])),
            affected_node_ids=tuple(data.get("affected_node_ids", [])),
            affected_node_count=int(data.get("affected_node_count", 0)),
            node_depths=dict(data.get("node_depths", {})),
            maximum_dependency_depth=int(data.get("maximum_dependency_depth", 0)),
            critical_affected_node_ids=tuple(data.get("critical_affected_node_ids", [])),
            high_criticality_affected_node_ids=tuple(data.get("high_criticality_affected_node_ids", [])),
            weighted_impact_score=float(data.get("weighted_impact_score", 0.0)),
            coverage_ratio=float(cov) if cov is not None else None,
            is_complete=bool(data.get("is_complete", False)),
            explanation=str(data.get("explanation", "")),
            provenance_hash=str(data.get("provenance_hash", "")),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
        )
