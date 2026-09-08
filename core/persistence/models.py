"""
Task 22: Persistence + Hardening Data Models & Boundaries.

Defines immutable contracts for persisted records, append-only audit chains,
recovery diagnostic reports, and portable audit export bundles.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RecordType(str, Enum):
    """Enumeration of all persistable first-class artifacts across Tasks 17-21."""
    NETWORK_STATE = "NETWORK_STATE"
    DEMO_EVENT = "DEMO_EVENT"
    RECONSIDERATION_EVENT = "RECONSIDERATION_EVENT"
    TOPOLOGY_SNAPSHOT = "TOPOLOGY_SNAPSHOT"
    BLAST_RADIUS_ASSESSMENT = "BLAST_RADIUS_ASSESSMENT"
    AUTHORITY_DECISION = "AUTHORITY_DECISION"
    RESPONSE_ACTION = "RESPONSE_ACTION"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    EXECUTION_RECORD = "EXECUTION_RECORD"
    OUTCOME_VERIFICATION = "OUTCOME_VERIFICATION"
    OUTCOME_MISMATCH_HANDOFF = "OUTCOME_MISMATCH_HANDOFF"


@dataclass(frozen=True)
class StoredRecord:
    """
    Immutable representation of a persisted record in the store.
    """
    record_id: str
    record_type: RecordType
    schema_version: int
    payload: dict[str, Any]
    provenance_hash: str
    created_at_iso: str
    audit_sequence: int | None = None
    audit_hash: str | None = None

    def __post_init__(self) -> None:
        if not self.record_id:
            raise ValueError("record_id cannot be empty")
        if not isinstance(self.record_type, RecordType):
            raise TypeError(f"record_type must be RecordType, got {type(self.record_type).__name__}")
        if self.schema_version < 1:
            raise ValueError(f"schema_version must be >= 1, got {self.schema_version}")
        if not isinstance(self.payload, dict):
            raise TypeError(f"payload must be a dict, got {type(self.payload).__name__}")
        if not self.provenance_hash:
            raise ValueError("provenance_hash cannot be empty")
        if not self.created_at_iso:
            raise ValueError("created_at_iso cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "record_type": self.record_type.value,
            "schema_version": self.schema_version,
            "payload": self.payload,
            "provenance_hash": self.provenance_hash,
            "created_at_iso": self.created_at_iso,
            "audit_sequence": self.audit_sequence,
            "audit_hash": self.audit_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StoredRecord:
        return cls(
            record_id=str(data["record_id"]),
            record_type=RecordType(data["record_type"]),
            schema_version=int(data["schema_version"]),
            payload=dict(data["payload"]),
            provenance_hash=str(data["provenance_hash"]),
            created_at_iso=str(data["created_at_iso"]),
            audit_sequence=int(data["audit_sequence"]) if data.get("audit_sequence") is not None else None,
            audit_hash=str(data["audit_hash"]) if data.get("audit_hash") is not None else None,
        )


@dataclass(frozen=True)
class AuditChainEntry:
    """
    Immutable entry in the sequential append-only audit log.
    Chained cryptographically: audit_hash_n = SHA256(payload_hash || prev_audit_hash).
    """
    sequence: int
    record_type: RecordType
    record_id: str
    payload_hash: str
    prev_audit_hash: str
    audit_hash: str
    timestamp_iso: str

    def __post_init__(self) -> None:
        if self.sequence < 1:
            raise ValueError(f"sequence must be >= 1, got {self.sequence}")
        if not self.record_id:
            raise ValueError("record_id cannot be empty")
        if not self.payload_hash:
            raise ValueError("payload_hash cannot be empty")
        if not self.prev_audit_hash:
            raise ValueError("prev_audit_hash cannot be empty")
        if not self.audit_hash:
            raise ValueError("audit_hash cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "record_type": self.record_type.value,
            "record_id": self.record_id,
            "payload_hash": self.payload_hash,
            "prev_audit_hash": self.prev_audit_hash,
            "audit_hash": self.audit_hash,
            "timestamp_iso": self.timestamp_iso,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditChainEntry:
        return cls(
            sequence=int(data["sequence"]),
            record_type=RecordType(data["record_type"]),
            record_id=str(data["record_id"]),
            payload_hash=str(data["payload_hash"]),
            prev_audit_hash=str(data["prev_audit_hash"]),
            audit_hash=str(data["audit_hash"]),
            timestamp_iso=str(data["timestamp_iso"]),
        )


@dataclass(frozen=True)
class RecoveryReport:
    """
    Diagnostic report produced by startup consistency and recovery verification.
    """
    is_consistent: bool
    total_records: int
    corrupted_records: tuple[str, ...] = field(default_factory=tuple)
    orphaned_records: tuple[str, ...] = field(default_factory=tuple)
    schema_errors: tuple[str, ...] = field(default_factory=tuple)
    diagnostics: tuple[str, ...] = field(default_factory=tuple)
    checked_at_iso: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_consistent": self.is_consistent,
            "total_records": self.total_records,
            "corrupted_records": list(self.corrupted_records),
            "orphaned_records": list(self.orphaned_records),
            "schema_errors": list(self.schema_errors),
            "diagnostics": list(self.diagnostics),
            "checked_at_iso": self.checked_at_iso,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RecoveryReport:
        return cls(
            is_consistent=bool(data["is_consistent"]),
            total_records=int(data["total_records"]),
            corrupted_records=tuple(data.get("corrupted_records", ())),
            orphaned_records=tuple(data.get("orphaned_records", ())),
            schema_errors=tuple(data.get("schema_errors", ())),
            diagnostics=tuple(data.get("diagnostics", ())),
            checked_at_iso=str(data.get("checked_at_iso", "")),
        )


@dataclass(frozen=True)
class AuditBundle:
    """
    Self-contained, deterministic audit export package.
    """
    bundle_id: str
    schema_version: int
    exported_at_iso: str
    record_count: int
    records: tuple[dict[str, Any], ...]
    audit_chain: tuple[dict[str, Any], ...]
    bundle_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "schema_version": self.schema_version,
            "exported_at_iso": self.exported_at_iso,
            "record_count": self.record_count,
            "records": list(self.records),
            "audit_chain": list(self.audit_chain),
            "bundle_hash": self.bundle_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditBundle:
        return cls(
            bundle_id=str(data["bundle_id"]),
            schema_version=int(data["schema_version"]),
            exported_at_iso=str(data["exported_at_iso"]),
            record_count=int(data["record_count"]),
            records=tuple(dict(r) for r in data.get("records", ())),
            audit_chain=tuple(dict(c) for c in data.get("audit_chain", ())),
            bundle_hash=str(data["bundle_hash"]),
        )
