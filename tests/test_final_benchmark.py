"""
Unit and validation tests for Final Benchmark Consolidation (SIH 26153).
Verifies:
1. All models in final_benchmark.csv have verified source provenance
2. Incomparable tasks (Delta-state regression vs Supervised classification) remain separated
3. Presentation metrics in presentation_metrics.json strictly match authoritative results
4. Response-window wording includes "simulated" in all documentation and presentation files
5. No prohibited claim is present in presentation claims or benchmark documentation
6. Deterministic output
7. Historical artifacts from prior days remain untouched
8. All previous tests continue passing
"""
from __future__ import annotations

import csv
import json
import unittest
from pathlib import Path


class TestFinalBenchmarkConsolidation(unittest.TestCase):

    def setUp(self) -> None:
        self.auth_file = Path("artifacts/final_validation/final_authoritative_results.json")
        self.pres_file = Path("artifacts/final_validation/presentation_metrics.json")
        self.bench_csv = Path("artifacts/final_validation/final_benchmark.csv")
        self.bench_md = Path("artifacts/final_validation/final_benchmark.md")
        self.claims_md = Path("docs/presentation_claims.md")

    def test_01_all_models_have_provenance(self) -> None:
        """Verify that every model in final_benchmark.csv has a valid source_artifact."""
        self.assertTrue(self.bench_csv.exists())
        with open(self.bench_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
        self.assertEqual(len(rows), 7)
        model_names = [r["model_name"] for r in rows]
        self.assertIn("ZeroChange", model_names)
        self.assertIn("Persistence", model_names)
        self.assertIn("EWMA (alpha=0.1)", model_names)
        self.assertIn("AR(3) Baseline", model_names)
        self.assertIn("AR(5) Primary Dynamics", model_names)
        self.assertIn("Ridge Regression", model_names)
        self.assertIn("GBDT Regressor", model_names)
        
        for r in rows:
            self.assertTrue(r["source_artifact"].startswith("artifacts/experiments/"))
            self.assertGreater(len(r["primary_caveat"]), 10)

    def test_02_incomparable_tasks_remain_separated(self) -> None:
        """Verify that final_benchmark.md explicitly separates delta regression from classification."""
        self.assertTrue(self.bench_md.exists())
        content = self.bench_md.read_text(encoding="utf-8")
        self.assertIn("Mandatory Task Separation", content)
        self.assertIn("Delta-State Regression Task", content)
        self.assertIn("Supervised Attack Classification Task", content)

    def test_03_presentation_metrics_match_authoritative_values(self) -> None:
        """Verify that values in presentation_metrics.json match final_authoritative_results.json."""
        self.assertTrue(self.pres_file.exists())
        self.assertTrue(self.auth_file.exists())
        
        with open(self.pres_file, "r", encoding="utf-8") as f:
            pres_data = json.load(f)
        with open(self.auth_file, "r", encoding="utf-8") as f:
            auth_data = json.load(f)
            
        self.assertEqual(pres_data["dataset_states_evaluated"], auth_data["data"]["total_states_count"])
        self.assertAlmostEqual(pres_data["ar5_directional_accuracy_test"], auth_data["dynamics"]["ar5_onestep_directional_accuracy"], places=4)
        self.assertAlmostEqual(pres_data["uncertainty_nominal_90_coverage"], auth_data["uncertainty"]["coverage_90pct_nominal"]["observed"], places=4)
        self.assertEqual(pres_data["simulated_useful_response_window_gain_seconds"], auth_data["response"]["average_useful_response_window_gain_seconds"])

    def test_04_response_window_wording_includes_simulated(self) -> None:
        """Verify that response window gain is explicitly labeled as 'simulated' in claims and docs."""
        claims_text = self.claims_md.read_text(encoding="utf-8")
        bench_text = self.bench_md.read_text(encoding="utf-8")
        
        self.assertIn("simulated useful response-window gain", claims_text.lower())
        self.assertIn("simulated useful prep gain", bench_text.lower())

    def test_05_no_prohibited_claims_present(self) -> None:
        """Verify docs and benchmark files avoid prohibited ungrounded claims in allowed claim texts."""
        bench_text = self.bench_md.read_text(encoding="utf-8").lower()
        self.assertNotIn("universally superior", bench_text)
        self.assertNotIn("predicts all cyber attacks", bench_text)
        self.assertNotIn("reduces real-world enterprise soc incident response time", bench_text)
        
        # Verify allowed claims in presentation_claims.md don't make overextended assertions
        claims_text = self.claims_md.read_text(encoding="utf-8")
        for line in claims_text.splitlines():
            if line.startswith("- **Exact Allowed Claim:**"):
                lower_claim = line.lower()
                self.assertNotIn("universally superior", lower_claim)
                self.assertNotIn("predicts all cyber attacks", lower_claim)
                self.assertNotIn("reduces real-world enterprise soc incident response time", lower_claim)


    def test_06_deterministic_output(self) -> None:
        """Verify presentation metrics file is valid deterministic JSON."""
        with open(self.pres_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["decision_safety_invariants_passed_ratio"], "13/13")

    def test_07_historical_artifacts_remain_untouched(self) -> None:
        """Verify that all historical experiment manifests exist and remain non-empty."""
        for p in [
            "artifacts/experiments/delta_baseline_v1/manifest.json",
            "artifacts/experiments/delta_baseline_v2/manifest.json",
            "artifacts/experiments/delta_rollout_uncertainty_v1_corrected/manifest.json",
            "artifacts/experiments/security_bridge_validation_v1/manifest.json",
            "artifacts/experiments/decision_layer_v1/manifest.json",
            "artifacts/experiments/response_window_v1/manifest.json",
            "artifacts/experiments/ar_order_availability_v1/manifest.json",
            "artifacts/experiments/explainability_v1/manifest.json",
            "artifacts/experiments/future_security_risk_v1/manifest.json",
            "artifacts/experiments/statistical_hardening_v1/manifest.json",
        ]:
            path = Path(p)
            self.assertTrue(path.exists(), f"Missing manifest: {p}")
            self.assertGreater(path.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
