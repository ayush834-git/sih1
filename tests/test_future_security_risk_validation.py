"""
Unit and Regression Tests for Future Security Risk Empirical Validation Harness (SIH PS 26153).

Verifies:
1. Chronological ordering preservation
2. Zero future leakage (provenance and truncation invariance)
3. Bounded risk scores: 0.0 <= R(t+h) <= 1.0
4. Output artifacts and schema integrity
5. Deterministic rerun reproducibility
6. Benign and attack dataset partitioning
7. Contradiction sequence integrity and risk suppression
8. Visual outputs existence, sizing, and valid PNG formatting
9. Moving block bootstrap temporal dependency preservation
"""
from __future__ import annotations

import csv
import json
import unittest
from datetime import datetime
from pathlib import Path

import numpy as np

from core.contracts import (
    STATE_SCHEMA_HASH,
    FeatureAvailability,
    NetworkState,
    Source,
    TrustLevel,
)
from eval.dataset import (
    CSV_AVAILABLE_FEATURES,
    load_states_from_jsonl,
)
from eval.rollout import MultiStepRolloutEngine
from eval.run_future_security_risk_validation import (
    compute_distribution_stats,
    evaluate_sequential_stream,
    moving_block_bootstrap_difference,
)
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.scenarios import get_demo_scenario_states
from security.bridge import BehavioralSecurityBridge
from security.risk_engine import SecurityRiskEngine


ROOT_DIR = Path(__file__).resolve().parent.parent
EXP_DIR = ROOT_DIR / "artifacts" / "experiments" / "future_security_risk_validation_v1"
FIGURES_DIR = EXP_DIR / "figures"
MODEL_DIR = ROOT_DIR / "artifacts" / "models" / "ar5_authoritative"
THU_PATH = ROOT_DIR / "artifacts" / "state_sequences" / "Thursday-01-03-2018_TrafficForML_CICFlowMeter.states.jsonl"


class TestFutureSecurityRiskValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ar_model, cls.scales = load_ar_model(MODEL_DIR)
        cls.rollout_engine = MultiStepRolloutEngine(cls.ar_model, CSV_AVAILABLE_FEATURES)
        cls.bridge = BehavioralSecurityBridge(scales=cls.scales)
        cls.risk_engine = SecurityRiskEngine()
        cls.demo_states = get_demo_scenario_states("demo_recon_15s")

    def test_01_chronological_ordering(self):
        """Verify evaluation streams preserve strict non-decreasing chronological order."""
        for i in range(len(self.demo_states) - 1):
            t_curr = self.demo_states[i].timestamp_start
            t_next = self.demo_states[i + 1].timestamp_start
            self.assertLessEqual(t_curr, t_next, "Timestamps must be non-decreasing")
            self.assertEqual(self.demo_states[i].timestamp_end, t_next, "Consecutive windows must meet continuously")

    def test_02_zero_future_leakage(self):
        """
        Demonstrate that future states, future labels, and future window truncation
        have zero effect on the computed risk trajectory at window t.
        """
        # Stream 1: Full 16-step demo sequence
        recs_full = evaluate_sequential_stream(
            self.demo_states,
            source_split="demo_full",
            rollout_engine=self.rollout_engine,
            bridge=self.bridge,
            risk_engine=self.risk_engine,
        )

        # Stream 2: Truncated sequence ending at window index 7 (future windows 8..15 removed)
        recs_truncated = evaluate_sequential_stream(
            self.demo_states[:8],
            source_split="demo_truncated",
            rollout_engine=self.rollout_engine,
            bridge=self.bridge,
            risk_engine=self.risk_engine,
        )

        # Bitwise identical risk values for all steps 0..7
        for k in range(8):
            self.assertEqual(recs_full[k].r0, recs_truncated[k].r0, f"Leakage detected: r0 at window {k} differs under truncation")
            self.assertEqual(recs_full[k].r1, recs_truncated[k].r1, f"Leakage detected: r1 at window {k} differs under truncation")
            self.assertEqual(recs_full[k].r2, recs_truncated[k].r2, f"Leakage detected: r2 at window {k} differs under truncation")
            self.assertEqual(recs_full[k].r3, recs_truncated[k].r3, f"Leakage detected: r3 at window {k} differs under truncation")
            self.assertEqual(recs_full[k].primary_stage, recs_truncated[k].primary_stage)

    def test_03_bounded_risk_scores(self):
        """Verify that R(t+h) is strictly bounded in [0.0, 1.0] under all horizons and fixtures."""
        recs = evaluate_sequential_stream(
            self.demo_states,
            source_split="demo",
            rollout_engine=self.rollout_engine,
            bridge=self.bridge,
            risk_engine=self.risk_engine,
        )
        for r in recs:
            for h in (0, 1, 2, 3):
                score = getattr(r, f"r{h}")
                self.assertGreaterEqual(score, 0.0, f"R(t+{h}) score {score} < 0.0 at window {r.window_index}")
                self.assertLessEqual(score, 1.0, f"R(t+{h}) score {score} > 1.0 at window {r.window_index}")

    def test_04_output_artifacts_and_schema_integrity(self):
        """Verify all generated CSV and JSON files exist and conform to schema."""
        self.assertTrue(EXP_DIR.exists(), f"Experiment output dir missing: {EXP_DIR}")
        summary_path = EXP_DIR / "results_summary.json"
        manifest_path = EXP_DIR / "manifest.json"
        self.assertTrue(summary_path.exists(), "results_summary.json missing")
        self.assertTrue(manifest_path.exists(), "manifest.json missing")

        with open(summary_path, "r", encoding="utf-8") as f:
            summary = json.load(f)

        self.assertEqual(summary["experiment_id"], "future_security_risk_validation_v1")
        self.assertEqual(summary["status"], "COMPLETED")
        for key in ("experiment_a", "experiment_b", "experiment_c", "experiment_d", "experiment_e"):
            self.assertIn(key, summary, f"Section {key} missing from results_summary.json")

        # Verify CSV files
        for csv_name in ("benign_trajectory.csv", "attack_trajectory.csv", "benign_vs_attack_comparison.csv", "contradiction_analysis.csv", "horizon_analysis.csv"):
            csv_path = EXP_DIR / csv_name
            self.assertTrue(csv_path.exists(), f"{csv_name} missing")
            self.assertGreater(csv_path.stat().st_size, 100, f"{csv_name} is unexpectedly small")

    def test_05_deterministic_rerun(self):
        """Verify deterministic rerun produces bitwise identical risk scores and hashes."""
        run1 = evaluate_sequential_stream(
            self.demo_states[:5],
            source_split="det_test",
            rollout_engine=self.rollout_engine,
            bridge=self.bridge,
            risk_engine=self.risk_engine,
        )
        run2 = evaluate_sequential_stream(
            self.demo_states[:5],
            source_split="det_test",
            rollout_engine=self.rollout_engine,
            bridge=self.bridge,
            risk_engine=self.risk_engine,
        )
        for r1, r2 in zip(run1, run2):
            self.assertEqual(r1.r0, r2.r0)
            self.assertEqual(r1.r1, r2.r1)
            self.assertEqual(r1.r2, r2.r2)
            self.assertEqual(r1.r3, r2.r3)
            self.assertEqual(r1.provenance_hash, r2.provenance_hash)

    def test_06_benign_attack_partitioning(self):
        """Verify benign vs attack partitioning over the Thursday chronological test split."""
        thu_states = load_states_from_jsonl(THU_PATH)
        test_start = datetime(2018, 3, 1, 8, 19, 40)
        test_states = [s for s in thu_states if s.timestamp_start >= test_start and not s.is_empty]
        self.assertEqual(len(test_states), 1682, "Thursday test split must contain exactly 1682 non-empty states")

        b4_start = datetime(2018, 3, 1, 9, 57, 0)
        b4_end = datetime(2018, 3, 1, 10, 54, 0)

        attack_states = [s for s in test_states if b4_start <= s.timestamp_start <= b4_end]
        benign_states = [s for s in test_states if not (b4_start <= s.timestamp_start <= b4_end)]

        self.assertEqual(len(attack_states), 343, "Block 4 must contain exactly 343 states")
        self.assertEqual(len(benign_states), 1339, "Benign test windows must total exactly 1339")
        self.assertEqual(len(attack_states) + len(benign_states), len(test_states), "Partitions must be mutually exclusive and exhaustive")

    def test_07_contradiction_sequence_and_suppression(self):
        """Verify contradiction scenario contains correct phases and reduces risk upon reversal."""
        summary_path = EXP_DIR / "results_summary.json"
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        exp_d = data["experiment_d"]
        self.assertGreater(exp_d["escalation_peak_r0"], exp_d["contradiction_trough_r0"], "Contradiction must lower risk")
        self.assertGreater(exp_d["risk_reduction_on_reversal"], 0.05, "Risk reduction must be non-trivial (>0.05)")
        self.assertEqual(exp_d["trust_drop"], "0.85 -> 0.35")

    def test_08_all_visual_plots_exist_and_valid(self):
        """Verify all 6 publication-quality plots exist, exceed 10KB, and are valid PNG images."""
        expected_plots = [
            "plot1_benign_risk_trajectory.png",
            "plot2_attack_onset_trajectory.png",
            "plot3_benign_vs_attack_distribution.png",
            "plot4_risk_difference_slope.png",
            "plot5_horizon_comparison.png",
            "plot6_contradiction_termination.png",
        ]
        png_magic = b"\x89PNG\r\n\x1a\n"
        for p_name in expected_plots:
            p_path = FIGURES_DIR / p_name
            self.assertTrue(p_path.exists(), f"Plot {p_name} is missing from {FIGURES_DIR}")
            self.assertGreater(p_path.stat().st_size, 10000, f"Plot {p_name} is too small (<10KB)")
            with open(p_path, "rb") as f:
                header = f.read(8)
                self.assertEqual(header, png_magic, f"Plot {p_name} is not a valid PNG image")

    def test_09_moving_block_bootstrap(self):
        """Verify that moving block bootstrap difference produces valid confidence intervals."""
        rng = np.random.default_rng(42)
        arr1 = rng.normal(0.40, 0.05, 100)
        arr2 = rng.normal(0.20, 0.05, 100)
        res = moving_block_bootstrap_difference(arr1, arr2, block_size=10, n_boot=500, seed=42)

        self.assertIn("median_diff_95ci", res)
        self.assertIn("mean_diff_95ci", res)
        self.assertLess(res["median_diff_95ci"][0], res["median_diff_95ci"][1])
        self.assertLess(res["mean_diff_95ci"][0], res["mean_diff_95ci"][1])
        self.assertGreater(res["observed_median_diff"], 0.10)
        self.assertGreater(res["cohens_d"], 1.0)


if __name__ == "__main__":
    unittest.main()
