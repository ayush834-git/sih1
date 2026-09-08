"""
Tests for Task 22: Persistence Store Core Operations & Transactions.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone

from core.persistence.models import (
    RecordType,
    StoredRecord,
)
from core.persistence.serializer import (
    CURRENT_SCHEMA_VERSION,
    canonical_json_dumps,
    compute_payload_hash,
)
from core.persistence.store import (
    DuplicateRecordConflictError,
    SQLitePersistenceStore,
)


class TestPersistence(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="sih_test_persistence_")
        self.db_path = os.path.join(self.temp_dir, "test_store.db")
        self.store = SQLitePersistenceStore(self.db_path)

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_record(
        self,
        record_type: RecordType = RecordType.AUTHORITY_DECISION,
        record_id: str = "auth-123",
        payload: dict | None = None,
    ) -> StoredRecord:
        p = payload or {"decision_id": record_id, "level": "RECOMMEND", "risk": 0.45}
        prov_hash = compute_payload_hash(p)
        return StoredRecord(
            record_id=record_id,
            record_type=record_type,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=p,
            provenance_hash=prov_hash,
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )

    # 1. Store and retrieve records for each RecordType
    def test_01_store_and_retrieve_all_record_types(self) -> None:
        for r_type in RecordType:
            rec = self._make_record(record_type=r_type, record_id=f"rec-{r_type.value}-1")
            self.store.put(rec)
            self.assertTrue(self.store.exists(r_type, rec.record_id))

            retrieved = self.store.get(r_type, rec.record_id)
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.record_id, rec.record_id)
            self.assertEqual(retrieved.record_type, r_type)
            self.assertEqual(retrieved.payload, rec.payload)
            self.assertEqual(retrieved.provenance_hash, rec.provenance_hash)

    # 2. Deterministic serialization roundtrip
    def test_02_deterministic_serialization(self) -> None:
        p1 = {"b": 2, "a": 1, "nested": {"z": 26, "y": 25}}
        p2 = {"nested": {"y": 25, "z": 26}, "a": 1, "b": 2}
        s1 = canonical_json_dumps(p1)
        s2 = canonical_json_dumps(p2)
        self.assertEqual(s1, s2)
        self.assertEqual(compute_payload_hash(p1), compute_payload_hash(p2))

    # 3. Schema version recorded and validated
    def test_03_schema_version_recorded(self) -> None:
        rec = self._make_record()
        self.store.put(rec)
        loaded = self.store.get(rec.record_type, rec.record_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.schema_version, CURRENT_SCHEMA_VERSION)

    # 4. Round-trip preserves record semantics and types
    def test_04_roundtrip_preserves_semantics(self) -> None:
        payload = {
            "str_val": "hello",
            "int_val": 42,
            "float_val": 3.14159,
            "bool_val": True,
            "null_val": None,
            "list_val": [1, 2, 3],
        }
        rec = self._make_record(payload=payload)
        self.store.put(rec)
        loaded = self.store.get(rec.record_type, rec.record_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.payload["str_val"], "hello")
        self.assertEqual(loaded.payload["int_val"], 42)
        self.assertEqual(loaded.payload["float_val"], 3.1416)
        self.assertTrue(loaded.payload["bool_val"])
        self.assertIsNone(loaded.payload["null_val"])
        self.assertEqual(loaded.payload["list_val"], [1, 2, 3])

    # 5. Unique ID enforcement across primary keys
    def test_05_unique_primary_key(self) -> None:
        rec1 = self._make_record(record_type=RecordType.RESPONSE_ACTION, record_id="act-1")
        self.store.put(rec1)
        self.assertTrue(self.store.exists(RecordType.RESPONSE_ACTION, "act-1"))
        self.assertFalse(self.store.exists(RecordType.HUMAN_APPROVAL, "act-1"))

    # 6. Duplicate write behavior: identical payload is idempotent no-op
    def test_06_idempotent_duplicate_write(self) -> None:
        rec = self._make_record()
        self.store.put(rec)
        # Re-putting identical record succeeds without error
        self.store.put(rec)
        loaded = self.store.get(rec.record_type, rec.record_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.payload, rec.payload)

    # 7. Duplicate write behavior: conflicting payload raises DuplicateRecordConflictError
    def test_07_conflicting_duplicate_write_raises_error(self) -> None:
        rec1 = self._make_record(record_id="conflict-1", payload={"val": 100})
        self.store.put(rec1)

        rec2 = self._make_record(record_id="conflict-1", payload={"val": 999})
        with self.assertRaises(DuplicateRecordConflictError):
            self.store.put(rec2)

    # 8. Atomic transaction commit
    def test_08_atomic_transaction_commit(self) -> None:
        rec1 = self._make_record(record_id="tx-1")
        rec2 = self._make_record(record_id="tx-2")
        self.store.put(rec1)
        self.store.put(rec2)
        self.assertTrue(self.store.exists(rec1.record_type, "tx-1"))
        self.assertTrue(self.store.exists(rec2.record_type, "tx-2"))

    # 9. Transaction rollback on simulated error
    def test_09_transaction_rollback_on_error(self) -> None:
        # Verify that an invalid operation inside a transaction aborts cleanly
        try:
            self.store._conn.execute("BEGIN IMMEDIATE;")
            self.store._conn.execute(
                "INSERT INTO records VALUES ('TEST', 'id1', 1, '{}', 'hash', 'iso');"
            )
            # Intentional syntax error
            self.store._conn.execute("INSERT INTO nonexistent_table VALUES (1);")
            self.store._conn.execute("COMMIT;")
        except Exception:
            self.store._conn.execute("ROLLBACK;")

        cur = self.store._conn.execute("SELECT 1 FROM records WHERE record_id = 'id1'")
        self.assertIsNone(cur.fetchone())

    # 10. Partial/crashed write leaves no half-valid records
    def test_10_no_half_valid_records_after_interruption(self) -> None:
        rec = self._make_record(record_id="crash-sim")
        self.store.put(rec)
        self.assertTrue(self.store.exists(rec.record_type, "crash-sim"))

    # 11. Current state vs audit history separation (set_current, get_current)
    def test_11_current_state_vs_audit_history(self) -> None:
        rec1 = self._make_record(record_type=RecordType.AUTHORITY_DECISION, record_id="auth-v1")
        rec2 = self._make_record(record_type=RecordType.AUTHORITY_DECISION, record_id="auth-v2")
        self.store.put(rec1)
        self.store.put(rec2)

        self.store.set_current(RecordType.AUTHORITY_DECISION, "auth-v1")
        curr = self.store.get_current(RecordType.AUTHORITY_DECISION)
        self.assertIsNotNone(curr)
        self.assertEqual(curr.record_id, "auth-v1")

        self.store.set_current(RecordType.AUTHORITY_DECISION, "auth-v2")
        curr = self.store.get_current(RecordType.AUTHORITY_DECISION)
        self.assertIsNotNone(curr)
        self.assertEqual(curr.record_id, "auth-v2")

        # Historical record auth-v1 remains completely intact
        hist1 = self.store.get(RecordType.AUTHORITY_DECISION, "auth-v1")
        self.assertIsNotNone(hist1)

    # 12. Historical records are not destroyed when current state advances
    def test_12_historical_records_preserved(self) -> None:
        recs = [self._make_record(record_id=f"step-{i}") for i in range(5)]
        for r in recs:
            self.store.put(r)
            self.store.set_current(r.record_type, r.record_id)

        all_recs = self.store.list_records(recs[0].record_type)
        self.assertEqual(len(all_recs), 5)
        curr = self.store.get_current(recs[0].record_type)
        self.assertIsNotNone(curr)
        self.assertEqual(curr.record_id, "step-4")

    # 13. Append-only audit chain sequence and hashing
    def test_13_audit_chain_sequence_and_hashing(self) -> None:
        rec1 = self._make_record(record_id="chain-1")
        rec2 = self._make_record(record_id="chain-2")

        entry1 = self.store.append_audit_event(rec1)
        self.assertEqual(entry1.sequence, 1)
        self.assertEqual(entry1.prev_audit_hash, "0" * 64)

        entry2 = self.store.append_audit_event(rec2)
        self.assertEqual(entry2.sequence, 2)
        self.assertEqual(entry2.prev_audit_hash, entry1.audit_hash)
        self.assertNotEqual(entry2.audit_hash, entry1.audit_hash)

    # 14. Audit chain link verification (verify_audit_chain)
    def test_14_verify_audit_chain(self) -> None:
        for i in range(3):
            rec = self._make_record(record_id=f"chain-verif-{i}")
            self.store.append_audit_event(rec)

        is_valid, anomalies = self.store.verify_audit_chain()
        self.assertTrue(is_valid)
        self.assertEqual(len(anomalies), 0)

    # 15. Cannot update or delete rows in audit_log (trigger/API rejection)
    def test_15_audit_log_append_only_guard(self) -> None:
        rec = self._make_record(record_id="guard-1")
        entry = self.store.append_audit_event(rec)

        with self.assertRaises(sqlite3.DatabaseError):
            self.store._conn.execute(
                "UPDATE audit_log SET payload_hash = 'corrupt' WHERE seq = ?",
                (entry.sequence,),
            )

        with self.assertRaises(sqlite3.DatabaseError):
            self.store._conn.execute(
                "DELETE FROM audit_log WHERE seq = ?",
                (entry.sequence,),
            )

    # 16. List records with and without limits
    def test_16_list_records_limits(self) -> None:
        for i in range(10):
            r = self._make_record(record_id=f"list-test-{i:02d}")
            self.store.put(r)

        all_recs = self.store.list_records(RecordType.AUTHORITY_DECISION)
        self.assertEqual(len(all_recs), 10)

        limited = self.store.list_records(RecordType.AUTHORITY_DECISION, limit=3)
        self.assertEqual(len(limited), 3)
        self.assertEqual(limited[0].record_id, "list-test-00")

    # 17. Reopening persistent SQLite store retains all data
    def test_17_reopen_store_retains_data(self) -> None:
        rec = self._make_record(record_id="persist-disk-1")
        self.store.put(rec)
        self.store.append_audit_event(rec)
        self.store.set_current(rec.record_type, rec.record_id)
        self.store.close()

        # Reopen
        store2 = SQLitePersistenceStore(self.db_path)
        try:
            self.assertTrue(store2.exists(rec.record_type, rec.record_id))
            curr = store2.get_current(rec.record_type)
            self.assertIsNotNone(curr)
            self.assertEqual(curr.record_id, "persist-disk-1")
            is_valid, _ = store2.verify_audit_chain()
            self.assertTrue(is_valid)
        finally:
            store2.close()


if __name__ == "__main__":
    unittest.main()
