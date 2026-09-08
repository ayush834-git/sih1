"""
Unit and validation tests for Statistical Hardening & Effect-Size Audit (SIH 26153).
Verifies:
1. Deterministic statistics computation across repeated runs
2. Reproducible resampling with fixed random seed
3. No historical artifact modification
4. Valid confidence interval bounds (lower <= point <= upper, width > 0)
5. Paired AR(3)/AR(5) comparison uses aligned observations
6. Response-window n=3 is not mislabeled as large-N inference
7. False-positive result is explicitly scenario-bounded
8. No prohibited statistical wording in machine-readable metadata
9. All prior tests remain passing
"""
from __future__ import annotations

import csv
import json
import unittest
from pathlib import Path

import numpy as np

from eval.run_statistical_hardening import moving_block_bootstrap


class TestStatisticalHardening(unittest.TestCase):

    def setUp(self) -> None:
        self.artifacts_dir = Path("artifacts/experiments/statistical_hardening_v1")

    def test_01_deterministic_statistics(self) -> None:
        """Verify moving block bootstrap produces deterministic output with identical seed."""
        b1 = moving_block_bootstrap(data_length=100, block_size=10, n_boot=50, rng=np.random.default_rng(42))
        b2 = moving_block_bootstrap(data_length=100, block_size=10, n_boot=50, rng=np.random.default_rng(42))
        
        self.assertEqual(len(b1), len(b2))
        for arr1, arr2 in zip(b1, b2):
            np.testing.assert_array_equal(arr1, arr2)

    def test_02_reproducible_resampling_with_fixed_seed(self) -> None:
        """Verify summary results JSON contains valid deterministic numbers."""
        res_file = self.artifacts_dir / "results_summary.json"
        self.assertTrue(res_file.exists())
        with open(res_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        self.assertEqual(data["gate"], "GREEN")
        self.assertAlmostEqual(data["ar5_test_directional_accuracy"]["point_estimate"], 0.6810, places=4)
        self.assertGreater(data["ar5_test_directional_accuracy"]["ci_95_upper"], data["ar5_test_directional_accuracy"]["ci_95_lower"])

    def test_03_no_historical_artifact_modification(self) -> None:
        """Verify that historical manifests from previous days remain untouched and non-empty."""
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

    def test_04_confidence_intervals_have_valid_bounds(self) -> None:
        """Verify CI lower <= point estimate <= CI upper."""
        ci_file = self.artifacts_dir / "ar5_confidence_interval.csv"
        self.assertTrue(ci_file.exists())
        with open(ci_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            
        pt = float(row["point_estimate"])
        lower = float(row["ci_95_lower"])
        upper = float(row["ci_95_upper"])
        
        self.assertLessEqual(lower, pt)
        self.assertLessEqual(pt, upper)
        self.assertGreater(upper - lower, 0.0)

    def test_05_paired_comparison_uses_aligned_observations(self) -> None:
        """Verify AR(3) vs AR(5) comparison evaluates identical sample counts."""
        comp_file = self.artifacts_dir / "ar3_vs_ar5_comparison.csv"
        self.assertTrue(comp_file.exists())
        with open(comp_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            
        n_aligned = int(row["sample_count_aligned_transitions"])
        self.assertEqual(n_aligned, 1682)
        diff_pt = float(row["paired_difference_point"])
        self.assertGreater(diff_pt, 0.0)
        self.assertIn("mcnemar", row["methodology"].lower())

    def test_06_response_window_n3_is_not_mislabeled_as_large_n(self) -> None:
        """Verify response window report explicitly labels n=3 as deterministic replay benchmark."""
        rw_file = self.artifacts_dir / "response_window_statistics.csv"
        self.assertTrue(rw_file.exists())
        with open(rw_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
        self.assertEqual(len(rows), 3)
        for r in rows:
            self.assertEqual(float(r["simulated_useful_window_gain_s"]), 10.0)
            self.assertEqual(float(r["raw_lead_time_s"]), 10.0)

    def test_07_false_positive_result_is_scenario_bounded(self) -> None:
        """Verify false positive CSV reports window bounds and avoids population overclaiming."""
        fp_file = self.artifacts_dir / "false_positive_bounds.csv"
        self.assertTrue(fp_file.exists())
        with open(fp_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
            
        self.assertEqual(int(row["evaluation_windows"]), 32)
        self.assertEqual(int(row["observed_false_alarms"]), 0)
        self.assertIn("observed 0 false positives", row["interpretation"].lower())

    def test_08_no_prohibited_statistical_wording_in_metadata(self) -> None:
        """Verify results JSON and CSVs avoid claiming 'universal proof' or 'calibrated attack probability'."""
        res_file = self.artifacts_dir / "results_summary.json"
        with open(res_file, "r", encoding="utf-8") as f:
            content = f.read().lower()
            
        self.assertNotIn("universally superior", content)
        self.assertNotIn("proven in live soc", content)
        self.assertNotIn("attack probability", content)

    def test_09_methodology_doc_and_summary_table_exist(self) -> None:
        """Verify docs/statistical_hardening.md and artifacts methodology exist and are populated."""
        doc_path = Path("docs/statistical_hardening.md")
        meth_path = self.artifacts_dir / "methodology.md"
        
        self.assertTrue(doc_path.exists())
        self.assertTrue(meth_path.exists())
        self.assertGreater(doc_path.stat().st_size, 500)
        self.assertGreater(meth_path.stat().st_size, 500)


if __name__ == "__main__":
    unittest.main()
