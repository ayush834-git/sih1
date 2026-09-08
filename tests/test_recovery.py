"""
Tests for Task 22: Startup Recovery & Cross-Reference Integrity Verification.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone

from core.persistence.models import (
    RecordType,
    StoredRecord,
)
from core.persistence.recovery import RecoveryChecker
from core.persistence.serializer import (
    CURRENT_SCHEMA_VERSION,
    MissingSchemaVersionError,
    UnsupportedSchemaError,
    compute_payload_hash,
    validate_schema_version,
)
from core.persistence.store import SQLitePersistenceStore


class TestRecovery(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="sih_test_recovery_")
        self.db_path = os.path.join(self.temp_dir, "test_recovery.db")
        self.store = SQLitePersistenceStore(self.db_path)

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_auth(self, decision_id: str = "auth-1") -> StoredRecord:
        payload = {"decision_id": decision_id, "level": "HUMAN_APPROVAL_REQUIRED"}
        return StoredRecord(
            record_id=decision_id,
            record_type=RecordType.AUTHORITY_DECISION,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=compute_payload_hash(payload),
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )

    def _make_topo(self, snapshot_id: str = "topo-1") -> StoredRecord:
        payload = {"snapshot_id": snapshot_id, "availability": "KNOWN", "nodes": []}
        return StoredRecord(
            record_id=snapshot_id,
            record_type=RecordType.TOPOLOGY_SNAPSHOT,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=compute_payload_hash(payload),
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )

    def _make_action(
        self,
        action_id: str = "act-1",
        auth_id: str = "auth-1",
        window_id: str = "win-1",
        topo_id: str | None = None,
    ) -> StoredRecord:
        payload = {
            "action_id": action_id,
            "authority_decision_id": auth_id,
            "evidence_window_id": window_id,
            "topology_snapshot_id": topo_id,
        }
        return StoredRecord(
            record_id=action_id,
            record_type=RecordType.RESPONSE_ACTION,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=compute_payload_hash(payload),
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )

    def _make_approval(
        self,
        approval_id: str = "appr-1",
        action_id: str = "act-1",
        auth_id: str = "auth-1",
        window_id: str = "win-1",
        approved: bool = True,
    ) -> StoredRecord:
        payload = {
            "approval_id": approval_id,
            "action_id": action_id,
            "authority_decision_id": auth_id,
            "evidence_window_id": window_id,
            "approved": approved,
        }
        return StoredRecord(
            record_id=approval_id,
            record_type=RecordType.HUMAN_APPROVAL,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=compute_payload_hash(payload),
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )

    # 1. Startup consistency check passes on clean valid store
    def test_01_clean_store_recovery_passes(self) -> None:
        auth = self._make_auth()
        topo = self._make_topo()
        act = self._make_action(auth_id=auth.record_id, topo_id=topo.record_id)
        appr = self._make_approval(action_id=act.record_id, auth_id=auth.record_id)

        for r in [auth, topo, act, appr]:
            self.store.put(r)
            self.store.append_audit_event(r)

        report = RecoveryChecker.check_store(self.store)
        self.assertTrue(report.is_consistent)
        self.assertEqual(len(report.corrupted_records), 0)
        self.assertEqual(len(report.orphaned_records), 0)
        self.assertEqual(len(report.schema_errors), 0)

    # 2. Schema validation logic
    def test_02_supported_schema_version_loads(self) -> None:
        self.assertEqual(validate_schema_version(1), 1)

    def test_03_unsupported_future_schema_version_rejected(self) -> None:
        with self.assertRaises(UnsupportedSchemaError):
            validate_schema_version(CURRENT_SCHEMA_VERSION + 1)

    def test_04_missing_or_invalid_schema_version_rejected(self) -> None:
        with self.assertRaises(MissingSchemaVersionError):
            validate_schema_version(None)
        with self.assertRaises(MissingSchemaVersionError):
            validate_schema_version(0)
        with self.assertRaises(MissingSchemaVersionError):
            validate_schema_version("invalid")

    # 5. Orphaned ResponseAction referencing non-existent authority decision detected
    def test_05_orphaned_action_detected(self) -> None:
        act = self._make_action(auth_id="nonexistent-auth")
        self.store.put(act)

        report = RecoveryChecker.check_store(self.store)
        self.assertFalse(report.is_consistent)
        self.assertTrue(any("RESPONSE_ACTION:act-1" in r for r in report.orphaned_records))

    # 6. Orphaned HumanApproval referencing non-existent action detected
    def test_06_orphaned_approval_detected(self) -> None:
        auth = self._make_auth()
        self.store.put(auth)
        appr = self._make_approval(action_id="nonexistent-act", auth_id=auth.record_id)
        self.store.put(appr)

        report = RecoveryChecker.check_store(self.store)
        self.assertFalse(report.is_consistent)
        self.assertTrue(any("HUMAN_APPROVAL:appr-1" in r for r in report.orphaned_records))

    # 7. Approval <-> Action token mismatch (authority_decision_id) detected
    def test_07_approval_action_auth_mismatch_detected(self) -> None:
        auth1 = self._make_auth(decision_id="auth-1")
        auth2 = self._make_auth(decision_id="auth-2")
        act = self._make_action(auth_id="auth-1")
        # Approval bound to auth-2 while action is bound to auth-1
        appr = self._make_approval(action_id=act.record_id, auth_id="auth-2")

        for r in [auth1, auth2, act, appr]:
            self.store.put(r)

        report = RecoveryChecker.check_store(self.store)
        self.assertFalse(report.is_consistent)
        self.assertTrue(any("HUMAN_APPROVAL:appr-1" in r for r in report.orphaned_records))

    # 8. ExecutionRecord marked EXECUTED referencing non-approved approval detected
    def test_08_executed_without_approved_approval_detected(self) -> None:
        auth = self._make_auth()
        act = self._make_action(auth_id=auth.record_id)
        appr = self._make_approval(action_id=act.record_id, auth_id=auth.record_id, approved=False)

        exec_payload = {
            "execution_id": "exec-1",
            "action_id": act.record_id,
            "authority_decision_id": auth.record_id,
            "approval_id": appr.record_id,
            "status": "EXECUTED",  # Conflict! Approval is False
        }
        exec_rec = StoredRecord(
            record_id="exec-1",
            record_type=RecordType.EXECUTION_RECORD,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=exec_payload,
            provenance_hash=compute_payload_hash(exec_payload),
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )

        for r in [auth, act, appr, exec_rec]:
            self.store.put(r)

        report = RecoveryChecker.check_store(self.store)
        self.assertFalse(report.is_consistent)
        self.assertTrue(any("EXECUTION_RECORD:exec-1" in r for r in report.orphaned_records))

    # 9. Orphaned BlastRadiusAssessment detected
    def test_09_orphaned_blast_radius_detected(self) -> None:
        payload = {
            "assessment_id": "br-1",
            "root_node_id": "db-1",
            "topology_snapshot_id": "nonexistent-topo",
            "affected_node_ids": ["api-1"],
        }
        br_rec = StoredRecord(
            record_id="br-1",
            record_type=RecordType.BLAST_RADIUS_ASSESSMENT,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=compute_payload_hash(payload),
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )
        self.store.put(br_rec)

        report = RecoveryChecker.check_store(self.store)
        self.assertFalse(report.is_consistent)
        self.assertTrue(any("BLAST_RADIUS_ASSESSMENT:br-1" in r for r in report.orphaned_records))

    # 10. Broken audit chain detected during recovery
    def test_10_broken_audit_chain_detected(self) -> None:
        auth = self._make_auth()
        self.store.append_audit_event(auth)

        # Directly corrupt prev_audit_hash in the database bypassing triggers
        self.store._conn.execute("DROP TRIGGER trg_audit_no_update;")
        self.store._conn.execute(
            "UPDATE audit_log SET prev_audit_hash = 'BROKEN_HASH' WHERE seq = 1;"
        )

        report = RecoveryChecker.check_store(self.store)
        self.assertFalse(report.is_consistent)
        self.assertTrue(any("Audit chain broken" in d for d in report.diagnostics))

    # 11. Diagnostic messages in recovery report are structured and non-empty
    def test_11_recovery_report_serialization(self) -> None:
        auth = self._make_auth()
        self.store.put(auth)
        report = RecoveryChecker.check_store(self.store)
        d = report.to_dict()
        self.assertTrue(d["is_consistent"])
        self.assertEqual(d["total_records"], 1)

        restored = report.from_dict(d)
        self.assertEqual(restored.is_consistent, report.is_consistent)
        self.assertEqual(restored.total_records, report.total_records)


if __name__ == "__main__":
    unittest.main()
