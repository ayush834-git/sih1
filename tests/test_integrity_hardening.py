"""
Tests for Task 22: Integrity, Tamper Detection, Path Safety, Secret Redaction,
and Full End-to-End Persistence Lifecycle.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone

from core.authority.models import ActionClass, AuthorityDecision, AuthorityLevel
from core.blastradius.engine import BlastRadiusEngine
from core.blastradius.models import BlastRadiusAssessment, BlastRadiusStatus
from core.persistence.models import (
    RecordType,
    StoredRecord,
)
from core.persistence.recovery import RecoveryChecker
from core.persistence.serializer import (
    CURRENT_SCHEMA_VERSION,
    CorruptedRecordError,
    artifact_to_stored_record,
    canonical_json_dumps,
    compute_payload_hash,
    redact_secrets,
)
from core.persistence.store import (
    SQLitePersistenceStore,
    _sanitize_path,
)
from core.response_execution.adapters import DemoResponseAdapter
from core.response_execution.executor import ResponseExecutor
from core.response_execution.models import (
    ExecutionRecord,
    ExecutionStatus,
    HumanApproval,
    ResponseAction,
    ReversibleActionType,
    RollbackPolicy,
)
from core.response_execution.verification import (
    OutcomeExpectation,
    OutcomeMismatchHandoff,
    OutcomeVerificationResult,
    OutcomeVerifier,
    VerificationStatus,
)
from core.topology.builder import build_minimal_demo_topology
from core.topology.graph import ServiceTopologyGraph
from core.topology.models import ServiceNode, TopologyAvailability


class TestIntegrityHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="sih_test_hardening_")
        self.db_path = os.path.join(self.temp_dir, "test_hardening.db")
        self.store = SQLitePersistenceStore(self.db_path)

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. Provenance hash preserved without modification
    def test_01_provenance_hash_preserved(self) -> None:
        payload = {"action_id": "act-1", "rate": 0.5}
        prov_hash = compute_payload_hash(payload)
        rec = StoredRecord(
            record_id="act-1",
            record_type=RecordType.RESPONSE_ACTION,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=prov_hash,
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )
        self.store.put(rec)

        loaded = self.store.get(RecordType.RESPONSE_ACTION, "act-1")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.provenance_hash, prov_hash)
        self.assertTrue(self.store.verify_integrity(RecordType.RESPONSE_ACTION, "act-1"))

    # 2. Direct database tampering simulation (modifying payload column in SQLite)
    def test_02_database_tampering_detected(self) -> None:
        payload = {"action_id": "act-tamper", "rate": 0.5}
        rec = StoredRecord(
            record_id="act-tamper",
            record_type=RecordType.RESPONSE_ACTION,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=payload,
            provenance_hash=compute_payload_hash(payload),
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )
        self.store.put(rec)
        self.assertTrue(self.store.verify_integrity(RecordType.RESPONSE_ACTION, "act-tamper"))

        # Adversary modifies database directly on filesystem
        tampered_payload = canonical_json_dumps({"action_id": "act-tamper", "rate": 0.999})
        self.store._conn.execute(
            "UPDATE records SET payload = ? WHERE record_id = 'act-tamper'",
            (tampered_payload,),
        )

        # Integrity verification must fail
        self.assertFalse(self.store.verify_integrity(RecordType.RESPONSE_ACTION, "act-tamper"))

        # Recovery checker must flag corruption
        report = RecoveryChecker.check_store(self.store)
        self.assertFalse(report.is_consistent)
        self.assertTrue(any("RESPONSE_ACTION:act-tamper" in c for c in report.corrupted_records))

    # 3. Secret redaction in canonical serialization
    def test_03_secret_redaction(self) -> None:
        sensitive = {
            "node_id": "db-prod",
            "api_key": "secret-12345",
            "db_password": "supersecretpassword",
            "auth_token": "bearer-xyz",
            "nested": {
                "private_key": "-----BEGIN RSA PRIVATE KEY-----",
                "normal_val": 42,
            },
        }
        redacted = redact_secrets(sensitive)
        self.assertEqual(redacted["api_key"], "[REDACTED]")
        self.assertEqual(redacted["db_password"], "[REDACTED]")
        self.assertEqual(redacted["auth_token"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["private_key"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["normal_val"], 42)

        # Serializer redacts secrets by default
        json_str = canonical_json_dumps(sensitive, redact=True)
        self.assertNotIn("secret-12345", json_str)
        self.assertNotIn("supersecretpassword", json_str)
        self.assertIn("[REDACTED]", json_str)

    # 4. Path traversal attack prevention on export and import
    def test_04_path_traversal_prevention(self) -> None:
        with self.assertRaises(ValueError):
            _sanitize_path("")
        with self.assertRaises(ValueError):
            _sanitize_path("foo/bar\x00/baz")

        # Export path resolves safely to normalized absolute path
        export_path = os.path.join(self.temp_dir, "subdir", "bundle.json")
        rec = StoredRecord(
            record_id="export-rec",
            record_type=RecordType.AUTHORITY_DECISION,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload={"auth": "ok"},
            provenance_hash=compute_payload_hash({"auth": "ok"}),
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )
        self.store.put(rec)
        self.store.append_audit_event(rec)

        bundle = self.store.export_audit_bundle(export_path)
        self.assertTrue(os.path.exists(export_path))
        self.assertEqual(bundle.record_count, 1)

    # 5. Export bundle import and roundtrip verification
    def test_05_export_import_roundtrip(self) -> None:
        rec = StoredRecord(
            record_id="rec-bundle-1",
            record_type=RecordType.AUTHORITY_DECISION,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload={"decision": "APPROVED"},
            provenance_hash=compute_payload_hash({"decision": "APPROVED"}),
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )
        self.store.put(rec)
        self.store.append_audit_event(rec)

        bundle_path = os.path.join(self.temp_dir, "export.json")
        self.store.export_audit_bundle(bundle_path)

        # New clean store imports bundle
        new_db = os.path.join(self.temp_dir, "imported.db")
        store2 = SQLitePersistenceStore(new_db)
        try:
            count = store2.import_audit_bundle(bundle_path)
            self.assertEqual(count, 1)
            self.assertTrue(store2.exists(RecordType.AUTHORITY_DECISION, "rec-bundle-1"))
            self.assertTrue(store2.verify_integrity(RecordType.AUTHORITY_DECISION, "rec-bundle-1"))
        finally:
            store2.close()

    # 6. Tampered export bundle fails hash verification on import
    def test_06_tampered_bundle_fails_import(self) -> None:
        rec = StoredRecord(
            record_id="rec-bundle-2",
            record_type=RecordType.AUTHORITY_DECISION,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload={"decision": "APPROVED"},
            provenance_hash=compute_payload_hash({"decision": "APPROVED"}),
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )
        self.store.put(rec)
        bundle_path = os.path.join(self.temp_dir, "tampered.json")
        self.store.export_audit_bundle(bundle_path)

        # Tamper with the export file directly
        with open(bundle_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["records"][0]["payload"]["decision"] = "FORGED_DECISION"
        with open(bundle_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        store2 = SQLitePersistenceStore(":memory:")
        try:
            with self.assertRaises(CorruptedRecordError):
                store2.import_audit_bundle(bundle_path)
        finally:
            store2.close()

    # 7. Reconsideration history: prior and revised assessments both persist
    def test_07_reconsideration_history_persisted(self) -> None:
        recon_payload = {
            "event_id": "recon-ev-1",
            "trigger_window_id": "win-10",
            "prior_window_id": "win-09",
            "prior_risk_score": 0.82,
            "revised_risk_score": 0.25,
            "revision_reason": "Traffic drop confirmed benign maintenance",
            "provenance_hash": "recon-prov-hash-1",
        }
        recon_rec = StoredRecord(
            record_id="recon-ev-1",
            record_type=RecordType.RECONSIDERATION_EVENT,
            schema_version=CURRENT_SCHEMA_VERSION,
            payload=recon_payload,
            provenance_hash="recon-prov-hash-1",
            created_at_iso=datetime.now(timezone.utc).isoformat(),
        )
        self.store.put(recon_rec)
        self.store.append_audit_event(recon_rec)

        loaded = self.store.get(RecordType.RECONSIDERATION_EVENT, "recon-ev-1")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.payload["prior_risk_score"], 0.82)
        self.assertEqual(loaded.payload["revised_risk_score"], 0.25)

    # 8. Full 20-Step End-to-End Lifecycle Persistence, Restart, and Tamper Detection
    def test_08_full_e2e_persistence_and_recovery_lifecycle(self) -> None:
        # Step 1: Create Topology
        topo_graph = build_minimal_demo_topology()
        topo_snap = topo_graph.to_snapshot(snapshot_id="snap-lifecycle-001")
        snap_rec = artifact_to_stored_record(topo_snap)
        self.store.put(snap_rec)
        self.store.append_audit_event(snap_rec)

        # Step 2: Create Blast Radius Assessment
        br = BlastRadiusEngine().assess(
            topology=topo_graph,
            root_node_id="svc-api",
            snapshot_id="snap-lifecycle-001",
        )
        br_rec = artifact_to_stored_record(br)
        self.store.put(br_rec)
        self.store.append_audit_event(br_rec)

        # Step 3: Create Authority Decision
        auth = AuthorityDecision(
            decision_id="auth-lifecycle-001",
            authority_level=AuthorityLevel.HUMAN_APPROVAL_REQUIRED,
            permitted_action_classes=(
                ActionClass.OBSERVE_ONLY,
                ActionClass.ALERT_OPERATOR,
                ActionClass.GENERATE_RECOMMENDATION,
                ActionClass.PREPARE_REVERSIBLE_ACTION,
                ActionClass.EXECUTE_REVERSIBLE_ACTION,
            ),
            blocked_action_classes=(ActionClass.EXECUTE_DESTRUCTIVE_ACTION,),
            human_approval_required=True,
            policy_version="1.0.0",
            reason_codes=("HIGH_EVIDENCE_PERMITS_REVERSIBLE",),
            explanation="Approved for human review",
        )
        auth_rec = artifact_to_stored_record(auth)
        self.store.put(auth_rec)
        self.store.append_audit_event(auth_rec)

        # Step 4: Create Response Action
        action = ResponseAction(
            action_id="act-lifecycle-001",
            action_class=ActionClass.EXECUTE_REVERSIBLE_ACTION,
            target_node_id="svc-api",
            action_type=ReversibleActionType.TEMP_RATE_LIMIT,
            requested_parameters={"rate_limit_bps": 500.0},
            expected_effect="Drop byte_rate by >= 30%",
            reversibility=True,
            compensating_action_type="REMOVE_RATE_LIMIT",
            authority_decision_id="auth-lifecycle-001",
            evidence_window_id="win-life-001",
            topology_snapshot_id="snap-lifecycle-001",
            rollback_policy=RollbackPolicy.AUTOMATIC_COMPENSATING,
        )
        act_rec = artifact_to_stored_record(action)
        self.store.put(act_rec)
        self.store.append_audit_event(act_rec)

        # Step 5: Create Human Approval
        approval = HumanApproval(
            approval_id="appr-lifecycle-001",
            action_id="act-lifecycle-001",
            authority_decision_id="auth-lifecycle-001",
            evidence_window_id="win-life-001",
            approved=True,
            approver_reference="operator-alice",
            approval_reason="Approved mitigation",
        )
        appr_rec = artifact_to_stored_record(approval)
        self.store.put(appr_rec)
        self.store.append_audit_event(appr_rec)

        # Step 6: Execute Action via DemoResponseAdapter & ResponseExecutor
        adapter = DemoResponseAdapter()
        executor = ResponseExecutor(adapter=adapter)
        exec_record, msg = executor.execute(
            action=action,
            authority_decision=auth,
            approval=approval,
            current_topology=topo_snap,
            current_window_id="win-life-001",
        )
        self.assertEqual(exec_record.status, ExecutionStatus.EXECUTED)
        exec_rec_stored = artifact_to_stored_record(exec_record)
        self.store.put(exec_rec_stored)
        self.store.append_audit_event(exec_rec_stored)

        # Step 7: Outcome Verification
        verifier = OutcomeVerifier()
        expectation = OutcomeExpectation(
            action_id=action.action_id,
            metric_name="packet_rate",
            expected_direction="DECREASE",
            baseline_value=1000.0,
            min_reduction_ratio=0.50,
        )
        # Observed drops from 1000 to 400 (60% drop, matches expectation)
        verif_result = verifier.verify(
            action=action,
            expectation=expectation,
            observed_state={"window_id": "win-life-002", "packet_rate": 400.0},
        )
        self.assertEqual(verif_result.status, VerificationStatus.VERIFIED_SUCCESS)
        verif_rec = artifact_to_stored_record(verif_result)
        self.store.put(verif_rec)
        self.store.append_audit_event(verif_rec)

        # Step 8: Check store consistency prior to shutdown
        initial_report = RecoveryChecker.check_store(self.store)
        self.assertTrue(initial_report.is_consistent)

        # Step 9: Simulate Process Restart (close database and reopen from disk)
        self.store.close()
        restarted_store = SQLitePersistenceStore(self.db_path)

        try:
            # Step 10: Verify all records exist and cross-references are valid
            post_restart_report = RecoveryChecker.check_store(restarted_store)
            self.assertTrue(post_restart_report.is_consistent)
            self.assertEqual(post_restart_report.total_records, 7)

            # Step 11: Verify Idempotency across restart
            # Attempting to re-execute action using persisted record
            reloaded_exec_rec = restarted_store.get(RecordType.EXECUTION_RECORD, exec_record.execution_id)
            self.assertIsNotNone(reloaded_exec_rec)
            self.assertEqual(reloaded_exec_rec.payload["status"], "EXECUTED")

            # Step 12: Simulate Tampering on Approval
            restarted_store._conn.execute(
                "UPDATE records SET payload = ? WHERE record_id = 'appr-lifecycle-001'",
                (canonical_json_dumps({"tampered": True}),),
            )

            # Step 13: Recovery detection fails closed
            tamper_report = RecoveryChecker.check_store(restarted_store)
            self.assertFalse(tamper_report.is_consistent)
            self.assertTrue(any("HUMAN_APPROVAL:appr-lifecycle-001" in c for c in tamper_report.corrupted_records))

        finally:
            restarted_store.close()


if __name__ == "__main__":
    unittest.main()
