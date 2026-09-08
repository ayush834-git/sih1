"""
Task 22: Persistence Serializer & Schema Versioning.

Provides deterministic canonical JSON serialization, schema versioning,
secret redaction, payload hash calculation, and artifact conversions.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any

from core.persistence.models import RecordType, StoredRecord

CURRENT_SCHEMA_VERSION = 1

SECRET_KEY_PATTERNS = (
    "password",
    "secret",
    "token",
    "api_key",
    "private_key",
    "credential",
    "auth_token",
    "privkey",
)


class UnsupportedSchemaError(Exception):
    """Raised when encountering an unsupported schema version."""


class MissingSchemaVersionError(Exception):
    """Raised when a record is missing a required schema version."""


class CorruptedRecordError(Exception):
    """Raised when record serialization/integrity fails."""


def _normalize_obj(obj: Any) -> Any:
    """Recursively normalize objects for deterministic serialization."""
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return round(obj, 4)
    if isinstance(obj, str):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        if obj.tzinfo is None:
            # Assume UTC if naive, or format cleanly
            return obj.replace(tzinfo=timezone.utc).isoformat()
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): _normalize_obj(v) for k, v in sorted(obj.items(), key=lambda x: str(x[0]))}
    if isinstance(obj, (list, tuple)):
        return [_normalize_obj(x) for x in obj]
    if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        return _normalize_obj(obj.to_dict())
    return str(obj)


def redact_secrets(data: Any) -> Any:
    """
    Recursively redact secret-like keys from dictionaries.
    """
    if isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(pattern in k_lower for pattern in SECRET_KEY_PATTERNS):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_secrets(v)
        return redacted
    if isinstance(data, list):
        return [redact_secrets(item) for item in data]
    if isinstance(data, tuple):
        return tuple(redact_secrets(item) for item in data)
    return data


def canonical_json_dumps(data: Any, redact: bool = True) -> str:
    """
    Deterministically serialize data to a canonical JSON string.
    Keys are sorted, separators are compact, floats are normalized.
    """
    normalized = _normalize_obj(data)
    if redact and isinstance(normalized, dict):
        normalized = redact_secrets(normalized)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"))


def canonical_json_loads(raw_json: str) -> dict[str, Any]:
    """
    Parse a JSON string into a dictionary.
    """
    try:
        val = json.loads(raw_json)
        if not isinstance(val, dict):
            raise CorruptedRecordError(f"Expected JSON object, got {type(val).__name__}")
        return val
    except Exception as exc:
        raise CorruptedRecordError(f"Failed to parse JSON: {exc}") from exc


def compute_payload_hash(payload: dict[str, Any]) -> str:
    """
    Compute deterministic SHA-256 hash over canonical JSON payload.
    """
    canonical_repr = canonical_json_dumps(payload, redact=False)
    return sha256(canonical_repr.encode("utf-8")).hexdigest()


def compute_audit_hash(payload_hash: str, prev_audit_hash: str) -> str:
    """
    Compute cryptographic link in the append-only audit chain.
    """
    link_repr = f"{payload_hash}|{prev_audit_hash}"
    return sha256(link_repr.encode("utf-8")).hexdigest()


def validate_schema_version(schema_version: Any) -> int:
    """
    Validate schema version. Rejects missing, invalid, or future schema versions.
    """
    if schema_version is None:
        raise MissingSchemaVersionError("schema_version is required")
    try:
        version = int(schema_version)
    except (ValueError, TypeError) as exc:
        raise MissingSchemaVersionError(f"Invalid schema_version: {schema_version}") from exc

    if version < 1:
        raise MissingSchemaVersionError(f"schema_version must be >= 1, got {version}")
    if version > CURRENT_SCHEMA_VERSION:
        raise UnsupportedSchemaError(
            f"Unsupported future schema_version {version} (current is {CURRENT_SCHEMA_VERSION})"
        )
    return version


def artifact_to_stored_record(artifact: Any) -> StoredRecord:
    """
    Convert any known first-class domain artifact into a StoredRecord.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. TopologySnapshot
    if hasattr(artifact, "snapshot_id") and hasattr(artifact, "nodes") and hasattr(artifact, "edges"):
        payload = _normalize_obj(artifact)
        prov_hash = getattr(artifact, "provenance_hash", "") or compute_payload_hash(payload)
        return StoredRecord(
            record_id=str(artifact.snapshot_id),
            record_type=RecordType.TOPOLOGY_SNAPSHOT,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=getattr(artifact, "created_at_iso", now_iso),
        )

    # 2. BlastRadiusAssessment
    if hasattr(artifact, "assessment_id") and hasattr(artifact, "root_node_id") and hasattr(artifact, "affected_node_ids"):
        payload = _normalize_obj(artifact)
        prov_hash = getattr(artifact, "provenance_hash", "") or compute_payload_hash(payload)
        return StoredRecord(
            record_id=str(artifact.assessment_id),
            record_type=RecordType.BLAST_RADIUS_ASSESSMENT,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=getattr(artifact, "assessed_at_iso", now_iso),
        )

    # 3. AuthorityDecision
    if hasattr(artifact, "decision_id") and hasattr(artifact, "authority_level") and hasattr(artifact, "permitted_action_classes"):
        payload = _normalize_obj(artifact)
        prov_hash = getattr(artifact, "provenance_hash", "") or compute_payload_hash(payload)
        return StoredRecord(
            record_id=str(artifact.decision_id),
            record_type=RecordType.AUTHORITY_DECISION,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=getattr(artifact, "evaluated_at_iso", now_iso),
        )

    # 4. ResponseAction
    if hasattr(artifact, "action_id") and hasattr(artifact, "action_type") and hasattr(artifact, "rollback_policy"):
        payload = _normalize_obj(artifact)
        prov_hash = getattr(artifact, "provenance_hash", "") or compute_payload_hash(payload)
        return StoredRecord(
            record_id=str(artifact.action_id),
            record_type=RecordType.RESPONSE_ACTION,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=now_iso,
        )

    # 5. HumanApproval
    if hasattr(artifact, "approval_id") and hasattr(artifact, "approver_reference") and hasattr(artifact, "approved"):
        payload = _normalize_obj(artifact)
        prov_hash = getattr(artifact, "provenance_hash", "") or compute_payload_hash(payload)
        return StoredRecord(
            record_id=str(artifact.approval_id),
            record_type=RecordType.HUMAN_APPROVAL,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=getattr(artifact, "approved_at_iso", now_iso) or now_iso,
        )

    # 6. ExecutionRecord
    if hasattr(artifact, "execution_id") and hasattr(artifact, "status") and hasattr(artifact, "applied_parameters"):
        payload = _normalize_obj(artifact)
        prov_hash = getattr(artifact, "provenance_hash", "") or compute_payload_hash(payload)
        return StoredRecord(
            record_id=str(artifact.execution_id),
            record_type=RecordType.EXECUTION_RECORD,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=getattr(artifact, "executed_at_iso", now_iso) or now_iso,
        )

    # 7. OutcomeVerificationResult
    if hasattr(artifact, "verification_id") and hasattr(artifact, "metric_name") and hasattr(artifact, "baseline_value"):
        payload = _normalize_obj(artifact)
        prov_hash = getattr(artifact, "provenance_hash", "") or compute_payload_hash(payload)
        created_at = getattr(artifact, "created_at", None)
        created_at_iso = created_at.isoformat() if hasattr(created_at, "isoformat") else now_iso
        return StoredRecord(
            record_id=str(artifact.verification_id),
            record_type=RecordType.OUTCOME_VERIFICATION,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=created_at_iso,
        )

    # 8. OutcomeMismatchHandoff
    if hasattr(artifact, "handoff_id") and hasattr(artifact, "conflict_description"):
        payload = _normalize_obj(artifact)
        prov_hash = compute_payload_hash(payload)
        created_at = getattr(artifact, "created_at", None)
        created_at_iso = created_at.isoformat() if hasattr(created_at, "isoformat") else now_iso
        return StoredRecord(
            record_id=str(artifact.handoff_id),
            record_type=RecordType.OUTCOME_MISMATCH_HANDOFF,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=created_at_iso,
        )

    # 9. ReconsiderationEvent
    if hasattr(artifact, "event_id") and hasattr(artifact, "trigger_window_id") and hasattr(artifact, "revised_risk_score"):
        payload = _normalize_obj(artifact)
        prov_hash = getattr(artifact, "provenance_hash", "") or compute_payload_hash(payload)
        created_at = getattr(artifact, "created_at", None)
        created_at_iso = created_at.isoformat() if hasattr(created_at, "isoformat") else now_iso
        return StoredRecord(
            record_id=str(artifact.event_id),
            record_type=RecordType.RECONSIDERATION_EVENT,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=created_at_iso,
        )

    # 10. DemoEvent
    if hasattr(artifact, "step_index") and hasattr(artifact, "scenario"):
        payload = _normalize_obj(artifact)
        rec_id = f"demoevent-{artifact.step_index}"
        prov_hash = getattr(artifact, "provenance_hash", "") or compute_payload_hash(payload)
        return StoredRecord(
            record_id=rec_id,
            record_type=RecordType.DEMO_EVENT,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=now_iso,
        )

    # 11. NetworkState
    if hasattr(artifact, "window_id") and hasattr(artifact, "session_id") and hasattr(artifact, "packet_rate"):
        payload = _normalize_obj(artifact)
        prov_hash = getattr(artifact, "provenance_hash", "") or compute_payload_hash(payload)
        ts_start = getattr(artifact, "timestamp_start", None)
        created_at_iso = ts_start.isoformat() if hasattr(ts_start, "isoformat") else now_iso
        return StoredRecord(
            record_id=str(artifact.window_id),
            record_type=RecordType.NETWORK_STATE,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=created_at_iso,
        )

    raise ValueError(f"Unsupported artifact type: {type(artifact).__name__}")
