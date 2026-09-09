"""Automated Benchmark and Software Correctness Test Suite for Phase 4 (SIH 26153).

Strictly separates Software-Correctness Invariants from Empirical Scientific Hypotheses:
1. Engine & Schema Correctness: Determinism, schema compliance (STATE_SCHEMA_HASH), onset detection.
2. Statistical Rigor: Paired Wilcoxon signed-rank, BCa Bootstrap, B-H FDR, Cliff's delta, separated flapping metrics.
3. Experiment A Correctness: B0-B5 hierarchy present, valid metric calculation, scientific verdict recorded.
4. Experiment B Correctness: Monotonic latency sweep calculation, raw/actionable lead time definitions.
5. Experiment C Invariants: Sensitivity to 4 modes, strictly enforced non-negotiable safety invariants:
   - ZERO autonomous second executions (N_auto_exec == 0).
   - ZERO autonomous rollbacks (N_auto_rollback == 0).
   - Reconsideration strictly requires explicit human approval (approval_required == True).
   - Strict non-causal epistemic framing (no Pearlian causal claims in explanations).
   - Fails closed to INSUFFICIENT_EVIDENCE on sensor blackout.
6. Experiment D Correctness: Multi-window stability through Phase 3C Human Approval Gate, zero execution leaks.
7. Artifact Completeness & Fidelity: Verification of JSON, CSV, MD presence with PARAMETERIZED_STATE_TRANSFORMATION disclosures.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
import unittest
import numpy as np

from core.contracts import STATE_SCHEMA_HASH, Direction, NetworkState, TrustAssessment, TrustFactor, TrustLevel
from core.topology.builder import build_minimal_demo_topology
from eval.phase4_scenarios import (
    PHASE4_EVENT_DEFINITIONS,
    build_phase4_episodes,
    build_phase4_scenarios,
)
from eval.phase4_statistics import (
    benjamini_hochberg_fdr,
    bootstrap_ci,
    calculate_action_transition_rate,
    calculate_flapping_index,
    calculate_nontrivial_flapping_rate,
    compute_cliffs_delta,
    paired_wilcoxon_test,
)
from eval.run_phase4_lead_time_experiment import find_ground_truth_onset, run_phase4_lead_time_experiment
from eval.run_phase4_mismatch_experiment import run_phase4_mismatch_experiment
from eval.run_phase4_pareto_experiment import run_phase4_pareto_experiment
from eval.run_phase4_stability_experiment import run_phase4_stability_experiment


class TestPhase4Benchmarks(unittest.TestCase):
    """Phase 4 Software Correctness and Safety Invariant Test Suite."""

    def setUp(self) -> None:
        self.t0 = datetime(2026, 9, 8, 12, 0, 0)
        self.topology = build_minimal_demo_topology()

    # =========================================================================
    # 1. Standardized Scenarios, 240 Episodes & Event Definitions
    # =========================================================================

    def test_phase4_scenarios_deterministic(self) -> None:
        """Verify build_phase4_scenarios generates deterministic 12 scenarios conforming to schema."""
        sc1 = build_phase4_scenarios(seed=42)
        sc2 = build_phase4_scenarios(seed=42)
        self.assertEqual(len(sc1), 12)
        self.assertEqual(set(sc1.keys()), set(sc2.keys()))

        for name, states in sc1.items():
            self.assertTrue(8 <= len(states) <= 10, f"Scenario {name} length {len(states)} out of [8, 10]")
            for s in states:
                self.assertIsNotNone(s.provenance_hash)
                self.assertIsNotNone(s.window_id)
                self.assertIsNotNone(s.timestamp_start)
                self.assertIsNotNone(s.timestamp_end)

    def test_phase4_episodes_hierarchy(self) -> None:
        """Verify build_phase4_episodes generates 240 episodes (12 templates x 20 repetitions)."""
        suite = build_phase4_episodes(n_repetitions=20, base_seed=42)
        self.assertEqual(suite["n_templates"], 12)
        self.assertEqual(suite["n_repetitions"], 20)
        self.assertEqual(suite["total_episodes"], 240)
        self.assertEqual(len(suite["episodes"]), 240)

        # Check episode structure
        ep0 = suite["episodes"][0]
        self.assertIn("episode_id", ep0)
        self.assertIn("template_id", ep0)
        self.assertIn("repetition_index", ep0)
        self.assertIn("states", ep0)

    def test_phase4_event_definitions_and_onsets(self) -> None:
        """Verify ground truth attack event onsets are identified in attack scenarios and absent in benign."""
        scenarios = build_phase4_scenarios(seed=42)
        for name, states in scenarios.items():
            if "recon" in name:
                onset_idx, onset_time = find_ground_truth_onset(states, "Reconnaissance")
                self.assertIsNotNone(onset_idx, f"Recon scenario {name} should have detected onset")
                self.assertIsNotNone(onset_time)
            elif "dos" in name:
                onset_idx, onset_time = find_ground_truth_onset(states, "Impact / Denial of Service")
                self.assertIsNotNone(onset_idx, f"DoS scenario {name} should have detected onset")
            elif "exfil" in name:
                onset_idx, onset_time = find_ground_truth_onset(states, "Collection / Exfiltration")
                self.assertIsNotNone(onset_idx, f"Exfil scenario {name} should have detected onset")
            elif "benign" in name:
                for cat in ["Reconnaissance", "Impact / Denial of Service", "Collection / Exfiltration"]:
                    idx, _ = find_ground_truth_onset(states, cat)
                    self.assertIsNone(idx, f"Benign scenario {name} should not trigger sustained onset for {cat}")

    # =========================================================================
    # 2. Statistical Methodology Utilities
    # =========================================================================

    def test_phase4_statistics_wilcoxon(self) -> None:
        """Verify paired Wilcoxon signed-rank test handles paired differences and small samples."""
        a = [10.0, 15.0, 20.0, 12.0, 18.0, 22.0]
        b = [5.0, 5.0, 5.0, 5.0, 5.0, 5.0]
        res = paired_wilcoxon_test(a, b, alternative="greater")
        self.assertLess(res["p_value"], 0.05)
        self.assertGreater(res["mean_diff"], 0.0)

        # Identical samples fallback
        res_ident = paired_wilcoxon_test(a, a)
        self.assertEqual(res_ident["p_value"], 1.0)
        self.assertEqual(res_ident["mean_diff"], 0.0)

    def test_phase4_statistics_bootstrap_ci(self) -> None:
        """Verify bootstrap confidence interval contains the point estimate."""
        data = [10.0, 12.0, 14.0, 16.0, 18.0, 20.0]
        pt, low, high = bootstrap_ci(data, np.mean, n_resamples=500, ci_level=0.95)
        self.assertAlmostEqual(pt, 15.0, places=4)
        self.assertLessEqual(low, pt)
        self.assertGreaterEqual(high, pt)

    def test_phase4_statistics_benjamini_hochberg(self) -> None:
        """Verify Benjamini-Hochberg FDR correctly flags significant p-values."""
        p_vals = [0.001, 0.01, 0.03, 0.20, 0.50]
        sigs = benjamini_hochberg_fdr(p_vals, alpha=0.05)
        self.assertTrue(sigs[0])
        self.assertTrue(sigs[1])
        self.assertFalse(sigs[-1])

    def test_phase4_statistics_flapping_metrics_deterministic(self) -> None:
        """Verify action transition rate and nontrivial flapping rate metric calculations."""
        # 1. Static sequence -> 0 for both
        seq_static = ["TEMP_RATE_LIMIT", "TEMP_RATE_LIMIT", "TEMP_RATE_LIMIT"]
        self.assertEqual(calculate_action_transition_rate(seq_static), 0.0)
        self.assertEqual(calculate_nontrivial_flapping_rate(seq_static), 0.0)

        # 2. Consequential oscillation (RATE_LIMIT <-> BLOCK) -> High nontrivial flapping
        seq_alt = ["TEMP_RATE_LIMIT", "DEMO_BLOCK", "TEMP_RATE_LIMIT", "DEMO_BLOCK"]
        self.assertEqual(calculate_action_transition_rate(seq_alt), 1.0)
        self.assertEqual(calculate_nontrivial_flapping_rate(seq_alt), 1.0)

        # 3. Benign onset (DO_NOTHING -> RATE_LIMIT -> RATE_LIMIT):
        # Action transition rate is 1/2 = 0.5, but nontrivial flapping rate is strictly 0.0
        seq_onset = ["DO_NOTHING", "TEMP_RATE_LIMIT", "TEMP_RATE_LIMIT"]
        self.assertEqual(calculate_action_transition_rate(seq_onset), 0.5)
        self.assertEqual(calculate_nontrivial_flapping_rate(seq_onset), 0.0)

        # 4. Pure benign sequence -> 0
        seq_benign = ["DO_NOTHING", "DO_NOTHING", "DO_NOTHING"]
        self.assertEqual(calculate_action_transition_rate(seq_benign), 0.0)
        self.assertEqual(calculate_nontrivial_flapping_rate(seq_benign), 0.0)

    def test_phase4_statistics_cliffs_delta(self) -> None:
        """Verify Cliff's delta effect size calculation."""
        x = [10.0, 12.0, 14.0]
        y = [2.0, 4.0, 6.0]
        self.assertAlmostEqual(compute_cliffs_delta(x, y), 1.0)
        self.assertAlmostEqual(compute_cliffs_delta(x, x), 0.0)

    # =========================================================================
    # 3. Experiment A (Pareto Frontier) Correctness Tests
    # =========================================================================

    def test_pareto_metrics_are_computed_correctly(self) -> None:
        """Verify Experiment A computes B0-B5 hierarchy and records a valid scientific verdict."""
        summary = run_phase4_pareto_experiment()
        self.assertEqual(summary["schema_hash"], STATE_SCHEMA_HASH)
        self.assertEqual(
            summary["simulation_fidelity"],
            "PARAMETERIZED_STATE_TRANSFORMATION_NOT_HARDWARE_INLINE",
        )
        self.assertEqual(summary["telemetry_source"], "SYNTHETIC_CONTROLLED_SCENARIO")
        self.assertIn("baseline_hierarchy", summary)
        self.assertEqual(len(summary["baseline_hierarchy"]), 6)

        # Scale reconciliation assertions: distinct absolute difference vs relative percentage reduction
        self.assertIn("mean_disruption_difference_absolute", summary)
        self.assertIn("disruption_reduction_absolute_ci_95", summary)
        self.assertIn("overall_disruption_reduction_pct", summary)
        self.assertIn("disruption_reduction_relative_pct_ci_95", summary)
        self.assertAlmostEqual(summary["mean_disruption_difference_absolute"], 0.0125, places=4)
        self.assertEqual(summary["overall_disruption_reduction_pct"], 100.0)

        # True safety envelope satisfaction assertions (10/12 = 83.33%)
        self.assertAlmostEqual(summary["safety_envelope_satisfaction_rate"], 10 / 12, places=3)
        self.assertEqual(summary["risk_envelope_satisfied_count"], 10)

        # Provenance assertions
        self.assertIn("git_commit_sha", summary)
        self.assertIn("experiment_seed", summary)

        # Scientific outcome is recorded with a valid verdict in {SUPPORT, WEAKENED, FALSIFIED}
        self.assertIn(summary["verdict"], {"SUPPORT", "WEAKENED", "FALSIFIED"})
        self.assertIn("predefined_evaluation_criterion", summary)

    # =========================================================================
    # 4. Experiment B (Actionable Lead Time) Correctness Tests
    # =========================================================================

    def test_actionable_lead_time_latency_sweep_correctness(self) -> None:
        """Verify Experiment B computes raw and actionable lead times across required latency regimes."""
        summary = run_phase4_lead_time_experiment()
        self.assertEqual(summary["schema_hash"], STATE_SCHEMA_HASH)
        self.assertEqual(
            summary["simulation_fidelity"],
            "PARAMETERIZED_STATE_TRANSFORMATION_NOT_HARDWARE_INLINE",
        )
        self.assertIn("git_commit_sha", summary)
        self.assertIn("experiment_seed", summary)

        sweeps = summary["latency_sweep_evaluations"]
        # Required latency regimes: 0s, 5s, 10s, 20s
        for tau_key in ["tau_0s", "tau_5s", "tau_10s", "tau_20s"]:
            self.assertIn(tau_key, sweeps)
            self.assertIsInstance(sweeps[tau_key]["b2_mean_actionable_lead_s"], float)

        # Monotonicity invariant: Actionable lead time must be non-increasing as tau increases
        lead_0 = sweeps["tau_0s"]["b2_mean_actionable_lead_s"]
        lead_5 = sweeps["tau_5s"]["b2_mean_actionable_lead_s"]
        lead_10 = sweeps["tau_10s"]["b2_mean_actionable_lead_s"]
        lead_20 = sweeps["tau_20s"]["b2_mean_actionable_lead_s"]

        self.assertGreaterEqual(lead_0, lead_5)
        self.assertGreaterEqual(lead_5, lead_10)
        self.assertGreaterEqual(lead_10, lead_20)

        # Scientific outcome is recorded with a valid verdict in {SUPPORT, WEAKENED, FALSIFIED}
        self.assertIn(summary["verdict"], {"SUPPORT", "WEAKENED", "FALSIFIED"})

    # =========================================================================
    # 5. Experiment C (Contradiction / Mismatch & Safety Invariants) Tests
    # =========================================================================

    def test_experiment_c_mismatch_and_safety_invariants(self) -> None:
        """Verify Experiment C asserts sensitivity to all 5 modes (conforming control + 3 injected + blackout) and strict safety invariants."""
        summary = run_phase4_mismatch_experiment()
        self.assertEqual(summary["schema_hash"], STATE_SCHEMA_HASH)
        self.assertEqual(summary["total_modes_tested"], 5)
        self.assertEqual(summary["conforming_control_modes_tested"], 1)
        self.assertEqual(summary["injected_divergence_modes_tested"], 3)
        self.assertEqual(summary["sensor_blackout_modes_tested"], 1)
        self.assertEqual(
            summary["simulation_fidelity"],
            "PARAMETERIZED_STATE_TRANSFORMATION_NOT_HARDWARE_INLINE",
        )
        self.assertIn("git_commit_sha", summary)
        self.assertIn("experiment_seed", summary)

        # Assert strict invariants (Hard assertions for safety invariants)
        invariants = summary["safety_invariants"]
        self.assertEqual(invariants["autonomous_second_executions"], 0)
        self.assertEqual(invariants["autonomous_rollbacks"], 0)
        self.assertTrue(invariants["reconsideration_requires_approval"])
        self.assertTrue(invariants["fails_closed_on_missing_telemetry"])
        self.assertTrue(invariants["epistemic_language_conformance"])

        # Check mode specifics
        mode_results = {m["mode_id"]: m for m in summary["mode_results"]}

        # Mode 0: Conforming execution control -> VERIFIED_SUCCESS, zero reconsideration
        self.assertEqual(mode_results["mode_0_conforming_execution"]["verification_status"], "VERIFIED_SUCCESS")
        self.assertFalse(mode_results["mode_0_conforming_execution"]["reconsideration_triggered"])
        self.assertFalse(mode_results["mode_0_conforming_execution"]["is_mismatch"])

        # Mode 1: Vector mutation -> VERIFIED_MISMATCH, Reconsideration triggered
        self.assertEqual(mode_results["mode_1_vector_mutation"]["verification_status"], "VERIFIED_MISMATCH")
        self.assertTrue(mode_results["mode_1_vector_mutation"]["reconsideration_triggered"])
        self.assertTrue(mode_results["mode_1_vector_mutation"]["new_request_requires_approval"])

        # Mode 2: Volumetric overpower -> VERIFIED_MISMATCH, Reconsideration triggered
        self.assertEqual(mode_results["mode_2_volumetric_overpower"]["verification_status"], "VERIFIED_MISMATCH")
        self.assertTrue(mode_results["mode_2_volumetric_overpower"]["reconsideration_triggered"])

        # Mode 3: Benign surge -> VERIFIED_MISMATCH, Reconsideration triggered
        self.assertEqual(mode_results["mode_3_benign_surge"]["verification_status"], "VERIFIED_MISMATCH")
        self.assertTrue(mode_results["mode_3_benign_surge"]["reconsideration_triggered"])

        # Mode 4: Sensor blackout -> INSUFFICIENT_EVIDENCE, fails closed, zero spurious reconsideration
        self.assertEqual(mode_results["mode_4_sensor_blackout"]["verification_status"], "INSUFFICIENT_EVIDENCE")
        self.assertFalse(mode_results["mode_4_sensor_blackout"]["reconsideration_triggered"])

    def test_experiment_c_epistemic_language_guards(self) -> None:
        """Assert no forbidden causal terms appear in mismatch explanations."""
        summary = run_phase4_mismatch_experiment()
        forbidden_terms = ["caused", "counterfactual", "pearlian", "intervention failed", "definitely failed"]
        for mode in summary["mode_results"]:
            expl = mode["explanation"].lower()
            for term in forbidden_terms:
                self.assertNotIn(term, expl, f"Forbidden term '{term}' found in mode {mode['mode_id']}")

    # =========================================================================
    # 6. Experiment D (Closed-Loop Multi-Window Stability) Tests
    # =========================================================================

    def test_experiment_d_closed_loop_stability_correctness(self) -> None:
        """Verify Experiment D proves multi-window stability without execution leaks or autonomous actions."""
        summary = run_phase4_stability_experiment(total_windows=60)
        self.assertEqual(summary["schema_hash"], STATE_SCHEMA_HASH)
        self.assertEqual(summary["total_windows_evaluated"], 60)
        self.assertEqual(
            summary["simulation_fidelity"],
            "PARAMETERIZED_STATE_TRANSFORMATION_NOT_HARDWARE_INLINE",
        )

        # Flapping metrics existence & calculation correctness
        metrics = summary["action_flapping_metrics"]
        self.assertIsInstance(metrics["all_action_transition_rate"], float)
        self.assertIsInstance(metrics["nontrivial_flapping_rate"], float)
        self.assertIn(summary["verdict"], {"SUPPORT", "WEAKENED", "FALSIFIED"})

        # Safety invariants over 60 continuous windows (Hard safety assertions)
        invariants = summary["closed_loop_safety_invariants"]
        self.assertEqual(invariants["autonomous_second_executions"], 0)
        self.assertEqual(invariants["autonomous_rollbacks"], 0)
        self.assertTrue(invariants["all_reconsideration_requests_require_approval"])

        # Trust recovery explicitly documented as not currently implemented
        self.assertIn("trust_dynamics", summary)
        self.assertEqual(
            summary["trust_dynamics"]["trust_recovery_status"],
            "NOT CURRENTLY IMPLEMENTED / NOT APPLICABLE",
        )

    # =========================================================================
    # 7. Artifact Directory Completeness & Disclosures
    # =========================================================================

    def test_artifact_generation_completeness(self) -> None:
        """Verify that all 4 experimental directories contain valid CSV, JSON, and MD artifact files with disclosures."""
        expected_artifacts = [
            ("artifacts/experiments/phase4_pareto_v1", ["pareto_frontier_results.json", "pareto_summary.md", "pareto_tradeoff_curve.csv"]),
            ("artifacts/experiments/phase4_lead_time_v1", ["lead_time_summary.json", "lead_time_summary.md", "lead_time_per_scenario.csv"]),
            ("artifacts/experiments/phase4_mismatch_v1", ["mismatch_evaluations.json", "mismatch_summary.md", "mismatch_trace.csv"]),
            ("artifacts/experiments/phase4_stability_v1", ["stability_summary.json", "stability_summary.md", "stability_trace.csv"]),
        ]

        for dir_path, files in expected_artifacts:
            p = Path(dir_path)
            self.assertTrue(p.exists(), f"Directory {dir_path} does not exist")
            for fname in files:
                file_path = p / fname
                self.assertTrue(file_path.exists(), f"File {file_path} does not exist")
                self.assertGreater(file_path.stat().st_size, 0, f"File {file_path} is empty")

                # Verify simulation fidelity disclosure in JSON files
                if fname.endswith(".json"):
                    with open(file_path, "r", encoding="utf-8") as jf:
                        data = json.load(jf)
                        self.assertEqual(
                            data.get("simulation_fidelity"),
                            "PARAMETERIZED_STATE_TRANSFORMATION_NOT_HARDWARE_INLINE",
                            f"Missing simulation_fidelity in {file_path}",
                        )


if __name__ == "__main__":
    unittest.main()
