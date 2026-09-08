"""
Task 22: Persistence + Hardening Layer for SIH PS 26153.
"""
from core.persistence.models import (
    AuditBundle,
    AuditChainEntry,
    RecordType,
    RecoveryReport,
    StoredRecord,
)
from core.persistence.recovery import RecoveryChecker
from core.persistence.serializer import (
    CURRENT_SCHEMA_VERSION,
    CorruptedRecordError,
    MissingSchemaVersionError,
    UnsupportedSchemaError,
    artifact_to_stored_record,
    canonical_json_dumps,
    canonical_json_loads,
    compute_audit_hash,
    compute_payload_hash,
    redact_secrets,
    validate_schema_version,
)
from core.persistence.store import (
    DuplicateRecordConflictError,
    PersistenceStore,
    SQLitePersistenceStore,
)

__all__ = [
    "AuditBundle",
    "AuditChainEntry",
    "CURRENT_SCHEMA_VERSION",
    "CorruptedRecordError",
    "DuplicateRecordConflictError",
    "MissingSchemaVersionError",
    "PersistenceStore",
    "RecordType",
    "RecoveryChecker",
    "RecoveryReport",
    "SQLitePersistenceStore",
    "StoredRecord",
    "UnsupportedSchemaError",
    "artifact_to_stored_record",
    "canonical_json_dumps",
    "canonical_json_loads",
    "compute_audit_hash",
    "compute_payload_hash",
    "redact_secrets",
    "validate_schema_version",
]
