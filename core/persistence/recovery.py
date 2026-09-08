"""
Task 22: Startup Recovery & Cross-Reference Integrity Checker.

Performs deterministic startup consistency verification, detecting malformed
records, unsupported schemas, broken audit chains, and orphaned or mismatched
cross-references across Tasks 17-21 artifacts.
"""
from __future__ import annotations

from typing import Any

from core.persistence.models import (
    RecordType,
    RecoveryReport,
    StoredRecord,
)
from core.persistence.serializer import (
    CURRENT_SCHEMA_VERSION,
    MissingSchemaVersionError,
    UnsupportedSchemaError,
    validate_schema_version,
)
from core.persistence.store import PersistenceStore


class RecoveryChecker:
    """
    Evaluates persistent store consistency and validates cross-reference integrity.
    """

    @classmethod
    def validate_cross_references(
        cls, record: StoredRecord, store: PersistenceStore
    ) -> tuple[bool, str]:
        """
        Validate cross-reference relationships between artifacts.
        Returns (is_valid, reason).
        """
        payload = record.payload

        # 1. RESPONSE_ACTION cross-references
        if record.record_type == RecordType.RESPONSE_ACTION:
            auth_id = payload.get("authority_decision_id")
            if not auth_id:
                return False, f"ResponseAction '{record.record_id}' missing authority_decision_id"
            if not store.exists(RecordType.AUTHORITY_DECISION, auth_id):
                return False, f"ResponseAction '{record.record_id}' references non-existent AuthorityDecision '{auth_id}'"

            topo_id = payload.get("topology_snapshot_id")
            if topo_id and not store.exists(RecordType.TOPOLOGY_SNAPSHOT, topo_id):
                return False, f"ResponseAction '{record.record_id}' references non-existent TopologySnapshot '{topo_id}'"

        # 2. HUMAN_APPROVAL cross-references
        elif record.record_type == RecordType.HUMAN_APPROVAL:
            action_id = payload.get("action_id")
            if not action_id:
                return False, f"HumanApproval '{record.record_id}' missing action_id"
            action_rec = store.get(RecordType.RESPONSE_ACTION, action_id)
            if action_rec is None:
                return False, f"HumanApproval '{record.record_id}' references non-existent ResponseAction '{action_id}'"

            auth_id = payload.get("authority_decision_id")
            if not auth_id:
                return False, f"HumanApproval '{record.record_id}' missing authority_decision_id"
            if not store.exists(RecordType.AUTHORITY_DECISION, auth_id):
                return False, f"HumanApproval '{record.record_id}' references non-existent AuthorityDecision '{auth_id}'"

            # Validate binding consistency between approval and action
            action_payload = action_rec.payload
            if action_payload.get("authority_decision_id") != auth_id:
                return (
                    False,
                    f"HumanApproval '{record.record_id}' authority_decision_id '{auth_id}' does not match action's '{action_payload.get('authority_decision_id')}'",
                )
            if action_payload.get("evidence_window_id") != payload.get("evidence_window_id"):
                return (
                    False,
                    f"HumanApproval '{record.record_id}' evidence_window_id does not match action's evidence_window_id",
                )

        # 3. EXECUTION_RECORD cross-references
        elif record.record_type == RecordType.EXECUTION_RECORD:
            action_id = payload.get("action_id")
            if not action_id:
                return False, f"ExecutionRecord '{record.record_id}' missing action_id"
            if not store.exists(RecordType.RESPONSE_ACTION, action_id):
                return False, f"ExecutionRecord '{record.record_id}' references non-existent ResponseAction '{action_id}'"

            auth_id = payload.get("authority_decision_id")
            if not auth_id:
                return False, f"ExecutionRecord '{record.record_id}' missing authority_decision_id"
            if not store.exists(RecordType.AUTHORITY_DECISION, auth_id):
                return False, f"ExecutionRecord '{record.record_id}' references non-existent AuthorityDecision '{auth_id}'"

            appr_id = payload.get("approval_id")
            status = payload.get("status")
            if appr_id:
                appr_rec = store.get(RecordType.HUMAN_APPROVAL, appr_id)
                if appr_rec is None:
                    return False, f"ExecutionRecord '{record.record_id}' references non-existent HumanApproval '{appr_id}'"
                # If executed, approval must have approved == True
                if status == "EXECUTED" and not appr_rec.payload.get("approved"):
                    return (
                        False,
                        f"ExecutionRecord '{record.record_id}' is EXECUTED but references non-approved HumanApproval '{appr_id}'",
                    )

        # 4. OUTCOME_VERIFICATION cross-references
        elif record.record_type == RecordType.OUTCOME_VERIFICATION:
            action_id = payload.get("action_id")
            if not action_id:
                return False, f"OutcomeVerification '{record.record_id}' missing action_id"
            if not store.exists(RecordType.RESPONSE_ACTION, action_id):
                return False, f"OutcomeVerification '{record.record_id}' references non-existent ResponseAction '{action_id}'"

        # 5. OUTCOME_MISMATCH_HANDOFF cross-references
        elif record.record_type == RecordType.OUTCOME_MISMATCH_HANDOFF:
            verif_id = payload.get("verification_id")
            if not verif_id:
                return False, f"OutcomeMismatchHandoff '{record.record_id}' missing verification_id"
            if not store.exists(RecordType.OUTCOME_VERIFICATION, verif_id):
                return False, f"OutcomeMismatchHandoff '{record.record_id}' references non-existent OutcomeVerification '{verif_id}'"

        # 6. BLAST_RADIUS_ASSESSMENT cross-references
        elif record.record_type == RecordType.BLAST_RADIUS_ASSESSMENT:
            topo_id = payload.get("topology_snapshot_id")
            if topo_id and not store.exists(RecordType.TOPOLOGY_SNAPSHOT, topo_id):
                return False, f"BlastRadiusAssessment '{record.record_id}' references non-existent TopologySnapshot '{topo_id}'"

        return True, "Valid"

    @classmethod
    def check_store(cls, store: PersistenceStore) -> RecoveryReport:
        """
        Execute full recovery diagnostics on a persistent store.
        """
        corrupted: list[str] = []
        orphaned: list[str] = []
        schema_errs: list[str] = []
        diagnostics: list[str] = []
        total_records = 0

        # 1. Audit chain continuous hash validation
        chain_valid, chain_anomalies = store.verify_audit_chain()
        if not chain_valid:
            diagnostics.extend(chain_anomalies)

        # 2. Iterate all record types and records
        for r_type in RecordType:
            records = store.list_records(r_type)
            for rec in records:
                total_records += 1

                # Schema check
                try:
                    validate_schema_version(rec.schema_version)
                except (UnsupportedSchemaError, MissingSchemaVersionError) as exc:
                    schema_errs.append(f"Record ({rec.record_type.value}, {rec.record_id}): {exc}")

                # Integrity / Tamper check
                if not store.verify_integrity(rec.record_type, rec.record_id):
                    corrupted.append(f"{rec.record_type.value}:{rec.record_id}")
                    diagnostics.append(
                        f"Integrity check failed for ({rec.record_type.value}, {rec.record_id}): hash mismatch or corrupted payload"
                    )

                # Cross-reference check
                is_valid, reason = cls.validate_cross_references(rec, store)
                if not is_valid:
                    orphaned.append(f"{rec.record_type.value}:{rec.record_id}")
                    diagnostics.append(reason)

        is_consistent = (
            len(corrupted) == 0
            and len(orphaned) == 0
            and len(schema_errs) == 0
            and chain_valid
        )

        return RecoveryReport(
            is_consistent=is_consistent,
            total_records=total_records,
            corrupted_records=tuple(corrupted),
            orphaned_records=tuple(orphaned),
            schema_errors=tuple(schema_errs),
            diagnostics=tuple(diagnostics),
        )
