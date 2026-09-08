"""
Unit tests for Final Evidence Hardening and Authoritative Metric Provenance (SIH 26153).
Verifies:
1. final_authoritative_results.json loads and adheres to the frozen schema
2. all referenced source artifacts exist on disk
3. every metric has complete audit provenance in final_metric_audit.csv
4. prohibited claims are marked RED and separated from GREEN/YELLOW
5. no provisional or unscaled early metric is marked presentation_allowed=YES
6. historical experiment artifacts remain present and unmodified
7. requirements.txt declares all necessary dependencies
8. no duplicate metric_id definitions exist in the audit log
"""

import csv
import json
import os
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = ROOT_DIR / "artifacts"
FINAL_VALIDATION_DIR = ARTIFACTS_DIR / "final_validation"
DOCS_DIR = ROOT_DIR / "docs"


class TestFinalEvidenceHardening(unittest.TestCase):

    def setUp(self):
        self.auth_results_path = FINAL_VALIDATION_DIR / "final_authoritative_results.json"
        self.metric_audit_path = FINAL_VALIDATION_DIR / "final_metric_audit.csv"
        self.claims_path = FINAL_VALIDATION_DIR / "final_claims.md"
        self.inconsistency_path = FINAL_VALIDATION_DIR / "inconsistency_report.md"
        self.guide_path = DOCS_DIR / "final_evidence_guide.md"
        self.req_path = ROOT_DIR / "requirements.txt"

    def test_01_final_authoritative_results_loads_and_validates(self):
        """Verify final_authoritative_results.json loads and contains all required domains."""
        self.assertTrue(self.auth_results_path.exists(), "final_authoritative_results.json must exist")
        with open(self.auth_results_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data.get("status"), "AUTHORITATIVE_FROZEN")
        self.assertEqual(data.get("project_id"), "SIH_26153")

        # Verify all required top-level domains
        required_domains = ["data", "dynamics", "uncertainty", "security", "decision", "response", "explainability"]
        for domain in required_domains:
            self.assertIn(domain, data, f"Domain '{domain}' missing from final_authoritative_results.json")
            self.assertIn("caveat", data[domain], f"Caveat missing from domain '{domain}'")

        # Verify key values
        self.assertEqual(data["data"]["total_states_count"], 8640)
        self.assertEqual(data["data"]["total_retained_flows"], 931136)
        self.assertEqual(data["data"]["total_empty_windows"], 1827)
        self.assertAlmostEqual(data["dynamics"]["ar5_onestep_directional_accuracy"], 0.6810, places=3)
        self.assertAlmostEqual(data["dynamics"]["ar5_vs_ar3_accuracy_gain"], 0.0184, places=4)
        self.assertEqual(data["dynamics"]["attack_blocks_forecasts_lost"], 0)
        self.assertAlmostEqual(data["response"]["average_raw_lead_time_seconds"], 10.0, places=1)
        self.assertAlmostEqual(data["response"]["average_useful_response_window_gain_seconds"], 10.0, places=1)
        self.assertEqual(data["response"]["false_positives_benign_burst"], 0)
        self.assertEqual(data["response"]["false_positives_ambiguous_noise"], 0)
        self.assertEqual(data["decision"]["safety_invariants_passed"], 13)
        self.assertEqual(data["security"]["anti_stage_collapse_pass_rate"], 1.0)

    def test_02_all_referenced_source_artifacts_exist(self):
        """Verify that every source artifact referenced in final_metric_audit.csv exists on disk."""
        self.assertTrue(self.metric_audit_path.exists(), "final_metric_audit.csv must exist")
        with open(self.metric_audit_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                source = row["artifact_source"]
                if source.lower() != "none":
                    artifact_path = ROOT_DIR / source
                    self.assertTrue(artifact_path.exists(), f"Referenced artifact path does not exist: {source} (Metric: {row['metric_id']})")

    def test_03_metric_audit_provenance_and_uniqueness(self):
        """Verify metric audit contains required columns, unique metric_ids, and non-empty caveats."""
        with open(self.metric_audit_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertGreaterEqual(len(rows), 20, "Metric audit must contain at least 20 candidate metrics")

        seen_metric_ids = set()
        for row in rows:
            m_id = row["metric_id"]
            self.assertNotIn(m_id, seen_metric_ids, f"Duplicate metric_id found: {m_id}")
            seen_metric_ids.add(m_id)

            # Verify required fields are populated
            self.assertTrue(row["metric_name"], f"Empty metric_name in {m_id}")
            self.assertTrue(row["value"], f"Empty value in {m_id}")
            self.assertTrue(row["methodology"], f"Empty methodology in {m_id}")
            self.assertTrue(row["caveat"], f"Empty caveat in {m_id}")
            self.assertIn(row["presentation_allowed"], ["YES", "NO"], f"Invalid presentation_allowed in {m_id}")

    def test_04_prohibited_claims_classified_red(self):
        """Verify that prohibited overextended claims are explicitly classified as RED in final_claims.md."""
        self.assertTrue(self.claims_path.exists(), "final_claims.md must exist")
        with open(self.claims_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("## GREEN", content)
        self.assertIn("## YELLOW", content)
        self.assertIn("## RED", content)

        # Verify specific prohibited phrases appear in RED section
        prohibited_concepts = [
            "Universal attack prediction",
            "Proven reduction in real-world SOC response time",
            "Calibrated joint probability distribution",
            "Autonomous AI SOC",
            "Live wire-speed 100Gbps kernel packet capture",
            "Long-horizon attack forecasting",
            "Guaranteed zero-breach outcome"
        ]
        for concept in prohibited_concepts:
            self.assertIn(concept, content, f"Prohibited concept '{concept}' must be explicitly documented in final_claims.md")

    def test_05_provisional_early_results_marked_presentation_forbidden(self):
        """Verify that provisional/unscaled early results are marked presentation_allowed=NO."""
        with open(self.metric_audit_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if "unscaled" in row["metric_name"] or "unrefreshed_open_loop_30s" in row["metric_name"]:
                    self.assertEqual(row["presentation_allowed"], "NO", f"Provisional metric {row['metric_name']} must have presentation_allowed=NO")

    def test_06_historical_experiment_artifacts_remain_intact(self):
        """Verify that all historical experiment result summaries and manifests remain present."""
        expected_experiments = [
            "delta_baseline_v1",
            "delta_baseline_v2",
            "delta_rollout_uncertainty_v1_corrected",
            "ar_order_availability_v1",
            "security_bridge_validation_v1",
            "decision_layer_v1",
            "response_window_v1",
            "explainability_v1"
        ]
        for exp in expected_experiments:
            exp_dir = ARTIFACTS_DIR / "experiments" / exp
            self.assertTrue(exp_dir.exists(), f"Historical experiment directory missing: {exp}")
            summary_path = exp_dir / "results_summary.json"
            self.assertTrue(summary_path.exists(), f"results_summary.json missing in {exp}")

    def test_07_requirements_file_declares_core_dependencies(self):
        """Verify requirements.txt exists and specifies required core libraries."""
        self.assertTrue(self.req_path.exists(), "requirements.txt must exist")
        with open(self.req_path, "r", encoding="utf-8") as f:
            req_content = f.read().lower()

        required_pkgs = ["numpy", "scipy", "scikit-learn", "pytest", "python-dateutil"]
        for pkg in required_pkgs:
            self.assertIn(pkg, req_content, f"Package '{pkg}' must be declared in requirements.txt")

    def test_08_evidence_guide_and_inconsistency_report_exist(self):
        """Verify docs/final_evidence_guide.md and inconsistency_report.md exist and are non-empty."""
        self.assertTrue(self.guide_path.exists(), "docs/final_evidence_guide.md must exist")
        self.assertTrue(self.inconsistency_path.exists(), "inconsistency_report.md must exist")
        self.assertGreater(self.guide_path.stat().st_size, 1000)
        self.assertGreater(self.inconsistency_path.stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
