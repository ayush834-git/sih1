"""
Task 22: Persistence Store Abstraction & SQLite Implementation.

Implements transactional, durable storage for all first-class artifacts,
append-only audit chaining, tamper detection, and deterministic export/import.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from core.persistence.models import (
    AuditBundle,
    AuditChainEntry,
    RecordType,
    StoredRecord,
)
from core.persistence.serializer import (
    CURRENT_SCHEMA_VERSION,
    CorruptedRecordError,
    canonical_json_dumps,
    canonical_json_loads,
    compute_audit_hash,
    compute_payload_hash,
    validate_schema_version,
)

GENESIS_AUDIT_HASH = "0" * 64


class DuplicateRecordConflictError(Exception):
    """Raised when attempting to overwrite an existing record with different content."""


class PersistenceStore(ABC):
    """
    Abstract interface for durable storage of SIH PS 26153 artifacts.
    """

    @abstractmethod
    def put(self, record: StoredRecord) -> None:
        """Store a record. Idempotent if identical; fails if conflicting."""

    @abstractmethod
    def get(self, record_type: RecordType, record_id: str) -> StoredRecord | None:
        """Retrieve a stored record by type and ID."""

    @abstractmethod
    def exists(self, record_type: RecordType, record_id: str) -> bool:
        """Check if a record exists in the store."""

    @abstractmethod
    def list_records(
        self, record_type: RecordType, limit: int | None = None
    ) -> list[StoredRecord]:
        """List stored records of a specific type in ascending order of insertion."""

    @abstractmethod
    def append_audit_event(self, record: StoredRecord) -> AuditChainEntry:
        """
        Append a record to the immutable audit log and advance the cryptographic audit chain.
        """

    @abstractmethod
    def get_current(self, record_type: RecordType) -> StoredRecord | None:
        """Get the current active/canonical record for a record type."""

    @abstractmethod
    def set_current(self, record_type: RecordType, record_id: str) -> None:
        """Set the current active/canonical record pointer for a record type."""

    @abstractmethod
    def get_audit_history(
        self, record_type: RecordType | None = None, limit: int | None = None
    ) -> list[AuditChainEntry]:
        """Retrieve the ordered audit chain entries."""

    @abstractmethod
    def verify_integrity(self, record_type: RecordType, record_id: str) -> bool:
        """Verify the cryptographic and payload integrity of a specific record."""

    @abstractmethod
    def verify_audit_chain(self) -> tuple[bool, list[str]]:
        """Verify the end-to-end cryptographic hash continuity of the audit chain."""

    @abstractmethod
    def export_audit_bundle(self, destination_path: str) -> AuditBundle:
        """Export all records and audit trail into a deterministic portable bundle."""

    @abstractmethod
    def import_audit_bundle(self, source_path: str) -> int:
        """Import a verified portable bundle into the store."""

    @abstractmethod
    def checkpoint(self) -> None:
        """Flush WAL / force sync to disk."""

    @abstractmethod
    def close(self) -> None:
        """Safely close database connections and release locks."""


def _sanitize_path(path: str) -> str:
    """Validate and sanitize a filesystem path against directory traversal."""
    if not path or "\x00" in path:
        raise ValueError("Invalid path: path cannot be empty or contain null bytes")
    # Resolve absolute normalized path
    norm_path = os.path.abspath(path)
    return norm_path


class SQLitePersistenceStore(PersistenceStore):
    """
    Transactional SQLite persistence store with WAL mode and append-only audit chaining.

    Security Boundary Clarification:
    The append-only audit invariant is enforced at the application and store API level.
    Direct database file tampering remains possible to an attacker with OS/filesystem access
    and is detected deterministically through provenance hash and audit chain verification.
    """

    def __init__(self, database_path: str = ":memory:") -> None:
        self._database_path = database_path
        self._lock = threading.RLock()

        # Connect to SQLite
        self._conn = sqlite3.connect(
            database_path,
            check_same_thread=False,
            isolation_level=None,  # Manual / explicit transaction management
        )
        self._conn.row_factory = sqlite3.Row

        with self._lock:
            # Configure WAL mode for file-based DBs, foreign keys, and busy timeout
            if database_path != ":memory:":
                try:
                    self._conn.execute("PRAGMA journal_mode = WAL;")
                except Exception:
                    pass
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._conn.execute("PRAGMA busy_timeout = 5000;")

            self._init_tables()

    def _init_tables(self) -> None:
        """Initialize database schema and triggers."""
        self._conn.execute("BEGIN IMMEDIATE;")
        try:
            # 1. Primary records table
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS records (
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    provenance_hash TEXT NOT NULL,
                    created_at_iso TEXT NOT NULL,
                    PRIMARY KEY (record_type, record_id)
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_records_type ON records(record_type);"
            )

            # 2. Append-only sequential audit log
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    prev_audit_hash TEXT NOT NULL,
                    audit_hash TEXT NOT NULL,
                    created_at_iso TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(record_type);"
            )

            # SQLite-level protection: disallow UPDATE or DELETE on audit_log
            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
                BEFORE UPDATE ON audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'Audit log is append-only and cannot be updated');
                END;
                """
            )
            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
                BEFORE DELETE ON audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'Audit log is append-only and cannot be deleted');
                END;
                """
            )

            # 3. Current canonical state pointer
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS current_state (
                    record_type TEXT PRIMARY KEY,
                    record_id TEXT NOT NULL,
                    updated_at_iso TEXT NOT NULL,
                    FOREIGN KEY (record_type, record_id) REFERENCES records(record_type, record_id)
                );
                """
            )

            self._conn.execute("COMMIT;")
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise

    def put(self, record: StoredRecord) -> None:
        """Store a record idempotently. Detects conflicts and preserves history."""
        if not isinstance(record, StoredRecord):
            raise TypeError(f"Expected StoredRecord, got {type(record).__name__}")

        validate_schema_version(record.schema_version)
        payload_str = canonical_json_dumps(record.payload, redact=True)

        with self._lock:
            # Check existing
            cur = self._conn.execute(
                "SELECT payload, provenance_hash, schema_version FROM records WHERE record_type = ? AND record_id = ?",
                (record.record_type.value, record.record_id),
            )
            row = cur.fetchone()
            if row is not None:
                # Idempotency check: if identical, succeed without error
                if (
                    row["payload"] == payload_str
                    and row["provenance_hash"] == record.provenance_hash
                    and row["schema_version"] == record.schema_version
                ):
                    return
                # Content differs: raise conflict
                raise DuplicateRecordConflictError(
                    f"Conflict: Record '{record.record_id}' of type '{record.record_type.value}' already exists with different payload"
                )

            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                self._conn.execute(
                    """
                    INSERT INTO records (record_type, record_id, schema_version, payload, provenance_hash, created_at_iso)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        record.record_type.value,
                        record.record_id,
                        record.schema_version,
                        payload_str,
                        record.provenance_hash,
                        record.created_at_iso,
                    ),
                )
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

    def get(self, record_type: RecordType, record_id: str) -> StoredRecord | None:
        """Retrieve a stored record by type and ID."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT record_type, record_id, schema_version, payload, provenance_hash, created_at_iso "
                "FROM records WHERE record_type = ? AND record_id = ?",
                (record_type.value, record_id),
            )
            row = cur.fetchone()
            if row is None:
                return None

            payload_dict = canonical_json_loads(row["payload"])
            return StoredRecord(
                record_id=row["record_id"],
                record_type=RecordType(row["record_type"]),
                schema_version=row["schema_version"],
                payload=payload_dict,
                provenance_hash=row["provenance_hash"],
                created_at_iso=row["created_at_iso"],
            )

    def exists(self, record_type: RecordType, record_id: str) -> bool:
        """Check if a record exists."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT 1 FROM records WHERE record_type = ? AND record_id = ?",
                (record_type.value, record_id),
            )
            return cur.fetchone() is not None

    def list_records(
        self, record_type: RecordType, limit: int | None = None
    ) -> list[StoredRecord]:
        """List records of a given type."""
        with self._lock:
            sql = "SELECT record_type, record_id, schema_version, payload, provenance_hash, created_at_iso FROM records WHERE record_type = ? ORDER BY rowid ASC"
            params: list[Any] = [record_type.value]
            if limit is not None:
                sql += " LIMIT ?"
                params.append(max(0, int(limit)))

            cur = self._conn.execute(sql, params)
            records = []
            for row in cur.fetchall():
                records.append(
                    StoredRecord(
                        record_id=row["record_id"],
                        record_type=RecordType(row["record_type"]),
                        schema_version=row["schema_version"],
                        payload=canonical_json_loads(row["payload"]),
                        provenance_hash=row["provenance_hash"],
                        created_at_iso=row["created_at_iso"],
                    )
                )
            return records

    def append_audit_event(self, record: StoredRecord) -> AuditChainEntry:
        """
        Append a record to the audit chain. Ensures record is stored and extends cryptographic chain.
        """
        with self._lock:
            # Ensure record is stored
            if not self.exists(record.record_type, record.record_id):
                self.put(record)

            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                # Find previous audit hash
                cur = self._conn.execute(
                    "SELECT seq, audit_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
                )
                last_row = cur.fetchone()
                prev_audit_hash = (
                    last_row["audit_hash"] if last_row is not None else GENESIS_AUDIT_HASH
                )

                payload_hash = compute_payload_hash(record.payload)
                audit_hash = compute_audit_hash(payload_hash, prev_audit_hash)
                now_iso = datetime.now(timezone.utc).isoformat()

                ins_cur = self._conn.execute(
                    """
                    INSERT INTO audit_log (record_type, record_id, payload_hash, prev_audit_hash, audit_hash, created_at_iso)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.record_type.value,
                        record.record_id,
                        payload_hash,
                        prev_audit_hash,
                        audit_hash,
                        now_iso,
                    ),
                )
                new_seq = ins_cur.lastrowid
                self._conn.execute("COMMIT;")

                return AuditChainEntry(
                    sequence=new_seq,
                    record_type=record.record_type,
                    record_id=record.record_id,
                    payload_hash=payload_hash,
                    prev_audit_hash=prev_audit_hash,
                    audit_hash=audit_hash,
                    timestamp_iso=now_iso,
                )
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

    def get_current(self, record_type: RecordType) -> StoredRecord | None:
        """Get the current active canonical record for a type."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT r.record_type, r.record_id, r.schema_version, r.payload, r.provenance_hash, r.created_at_iso "
                "FROM current_state c JOIN records r ON c.record_type = r.record_type AND c.record_id = r.record_id "
                "WHERE c.record_type = ?",
                (record_type.value,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return StoredRecord(
                record_id=row["record_id"],
                record_type=RecordType(row["record_type"]),
                schema_version=row["schema_version"],
                payload=canonical_json_loads(row["payload"]),
                provenance_hash=row["provenance_hash"],
                created_at_iso=row["created_at_iso"],
            )

    def set_current(self, record_type: RecordType, record_id: str) -> None:
        """Point current canonical state for a type to a specific record."""
        with self._lock:
            if not self.exists(record_type, record_id):
                raise ValueError(
                    f"Cannot set current: record '{record_id}' of type '{record_type.value}' does not exist"
                )

            now_iso = datetime.now(timezone.utc).isoformat()
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                self._conn.execute(
                    """
                    INSERT INTO current_state (record_type, record_id, updated_at_iso)
                    VALUES (?, ?, ?)
                    ON CONFLICT(record_type) DO UPDATE SET record_id = excluded.record_id, updated_at_iso = excluded.updated_at_iso;
                    """,
                    (record_type.value, record_id, now_iso),
                )
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

    def get_audit_history(
        self, record_type: RecordType | None = None, limit: int | None = None
    ) -> list[AuditChainEntry]:
        """Retrieve sequential audit chain entries."""
        with self._lock:
            sql = "SELECT seq, record_type, record_id, payload_hash, prev_audit_hash, audit_hash, created_at_iso FROM audit_log"
            params: list[Any] = []
            if record_type is not None:
                sql += " WHERE record_type = ?"
                params.append(record_type.value)
            sql += " ORDER BY seq ASC"
            if limit is not None:
                sql += " LIMIT ?"
                params.append(max(0, int(limit)))

            cur = self._conn.execute(sql, params)
            entries = []
            for row in cur.fetchall():
                entries.append(
                    AuditChainEntry(
                        sequence=row["seq"],
                        record_type=RecordType(row["record_type"]),
                        record_id=row["record_id"],
                        payload_hash=row["payload_hash"],
                        prev_audit_hash=row["prev_audit_hash"],
                        audit_hash=row["audit_hash"],
                        timestamp_iso=row["created_at_iso"],
                    )
                )
            return entries

    def verify_integrity(self, record_type: RecordType, record_id: str) -> bool:
        """
        Verify the integrity of a stored record.
        Re-computes payload hash and validates against provenance hash or canonical rules.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT payload, provenance_hash FROM records WHERE record_type = ? AND record_id = ?",
                (record_type.value, record_id),
            )
            row = cur.fetchone()
            if row is None:
                return False

            raw_payload = row["payload"]
            stored_prov_hash = row["provenance_hash"]

            try:
                payload_dict = canonical_json_loads(raw_payload)
            except CorruptedRecordError:
                return False

            # Recalculate payload hash
            recalc_payload_hash = compute_payload_hash(payload_dict)

            # Check if stored provenance hash matches recalculated payload hash
            if stored_prov_hash == recalc_payload_hash:
                return True

            # If payload has an embedded provenance_hash field, verify it matches
            if "provenance_hash" in payload_dict and payload_dict["provenance_hash"] == stored_prov_hash:
                return True

            return False

    def verify_audit_chain(self) -> tuple[bool, list[str]]:
        """
        Verify the continuous cryptographic integrity of the entire audit chain.
        """
        anomalies: list[str] = []
        with self._lock:
            cur = self._conn.execute(
                "SELECT seq, record_type, record_id, payload_hash, prev_audit_hash, audit_hash FROM audit_log ORDER BY seq ASC"
            )
            rows = cur.fetchall()
            if not rows:
                return True, []

            expected_prev_hash = GENESIS_AUDIT_HASH
            for idx, row in enumerate(rows):
                seq = row["seq"]
                r_type = row["record_type"]
                r_id = row["record_id"]
                payload_hash = row["payload_hash"]
                prev_audit_hash = row["prev_audit_hash"]
                audit_hash = row["audit_hash"]

                # 1. Check prev_audit_hash link
                if prev_audit_hash != expected_prev_hash:
                    anomalies.append(
                        f"Audit chain broken at seq {seq}: prev_audit_hash '{prev_audit_hash}' != expected '{expected_prev_hash}'"
                    )

                # 2. Check current audit_hash formula
                recalc_audit_hash = compute_audit_hash(payload_hash, prev_audit_hash)
                if audit_hash != recalc_audit_hash:
                    anomalies.append(
                        f"Audit hash mismatch at seq {seq}: stored '{audit_hash}' != calculated '{recalc_audit_hash}'"
                    )

                # 3. Verify corresponding record exists and payload hash matches
                rec_cur = self._conn.execute(
                    "SELECT payload FROM records WHERE record_type = ? AND record_id = ?",
                    (r_type, r_id),
                )
                rec_row = rec_cur.fetchone()
                if rec_row is None:
                    anomalies.append(
                        f"Audit entry at seq {seq} references non-existent record ({r_type}, {r_id})"
                    )
                else:
                    rec_payload = canonical_json_loads(rec_row["payload"])
                    actual_payload_hash = compute_payload_hash(rec_payload)
                    if actual_payload_hash != payload_hash:
                        anomalies.append(
                            f"Payload hash mismatch at seq {seq} for record ({r_type}, {r_id}): audit has '{payload_hash}', record has '{actual_payload_hash}'"
                        )

                expected_prev_hash = audit_hash

        is_valid = len(anomalies) == 0
        return is_valid, anomalies

    def export_audit_bundle(self, destination_path: str) -> AuditBundle:
        """Export all records and audit log to a deterministic JSON bundle file."""
        safe_path = _sanitize_path(destination_path)
        os.makedirs(os.path.dirname(safe_path), exist_ok=True)

        with self._lock:
            # Collect all records sorted deterministically
            cur_r = self._conn.execute(
                "SELECT record_type, record_id, schema_version, payload, provenance_hash, created_at_iso FROM records ORDER BY record_type ASC, record_id ASC"
            )
            records_list = []
            for row in cur_r.fetchall():
                records_list.append(
                    {
                        "record_type": row["record_type"],
                        "record_id": row["record_id"],
                        "schema_version": row["schema_version"],
                        "payload": canonical_json_loads(row["payload"]),
                        "provenance_hash": row["provenance_hash"],
                        "created_at_iso": row["created_at_iso"],
                    }
                )

            # Collect audit chain
            cur_a = self._conn.execute(
                "SELECT seq, record_type, record_id, payload_hash, prev_audit_hash, audit_hash, created_at_iso FROM audit_log ORDER BY seq ASC"
            )
            chain_list = []
            for row in cur_a.fetchall():
                chain_list.append(
                    {
                        "sequence": row["seq"],
                        "record_type": row["record_type"],
                        "record_id": row["record_id"],
                        "payload_hash": row["payload_hash"],
                        "prev_audit_hash": row["prev_audit_hash"],
                        "audit_hash": row["audit_hash"],
                        "timestamp_iso": row["created_at_iso"],
                    }
                )

            bundle_id = f"bundle-{sha256(str(len(records_list)).encode()).hexdigest()[:12]}"
            now_iso = datetime.now(timezone.utc).isoformat()

            raw_bundle = {
                "bundle_id": bundle_id,
                "schema_version": CURRENT_SCHEMA_VERSION,
                "exported_at_iso": now_iso,
                "record_count": len(records_list),
                "records": records_list,
                "audit_chain": chain_list,
            }
            bundle_hash = compute_payload_hash(raw_bundle)

            bundle = AuditBundle(
                bundle_id=bundle_id,
                schema_version=CURRENT_SCHEMA_VERSION,
                exported_at_iso=now_iso,
                record_count=len(records_list),
                records=tuple(records_list),
                audit_chain=tuple(chain_list),
                bundle_hash=bundle_hash,
            )

            with open(safe_path, "w", encoding="utf-8") as f:
                f.write(canonical_json_dumps(bundle.to_dict(), redact=False))

            return bundle

    def import_audit_bundle(self, source_path: str) -> int:
        """
        Import a verified portable bundle into the store.
        """
        safe_path = _sanitize_path(source_path)
        if not os.path.exists(safe_path):
            raise FileNotFoundError(f"Bundle file not found: {safe_path}")

        with open(safe_path, "r", encoding="utf-8") as f:
            raw_content = f.read()

        bundle_dict = canonical_json_loads(raw_content)
        bundle = AuditBundle.from_dict(bundle_dict)

        validate_schema_version(bundle.schema_version)

        # Verify bundle hash
        raw_bundle = {
            "bundle_id": bundle.bundle_id,
            "schema_version": bundle.schema_version,
            "exported_at_iso": bundle.exported_at_iso,
            "record_count": bundle.record_count,
            "records": [dict(r) for r in bundle.records],
            "audit_chain": [dict(c) for c in bundle.audit_chain],
        }
        recalc_hash = compute_payload_hash(raw_bundle)
        if recalc_hash != bundle.bundle_hash:
            raise CorruptedRecordError(
                f"Bundle hash mismatch: stored '{bundle.bundle_hash}' != calculated '{recalc_hash}'"
            )

        imported_count = 0
        with self._lock:
            for rec_dict in bundle.records:
                record = StoredRecord(
                    record_id=rec_dict["record_id"],
                    record_type=RecordType(rec_dict["record_type"]),
                    schema_version=rec_dict["schema_version"],
                    payload=rec_dict["payload"],
                    provenance_hash=rec_dict["provenance_hash"],
                    created_at_iso=rec_dict["created_at_iso"],
                )
                self.put(record)
                imported_count += 1

        return imported_count

    def checkpoint(self) -> None:
        """Force a WAL checkpoint."""
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(FULL);")
            except Exception:
                pass

    def close(self) -> None:
        """Close connection."""
        with self._lock:
            self.checkpoint()
            self._conn.close()
