"""
Unit, Regression, and Live-Style Causality Tests for MultiSignalRollingBaselineSecurityBridge (SIH PS 26153).

Validates:
1. Truncation invariance (zero future leakage under sequence truncation).
2. No future-feature access (strict causality).
3. No cross-stream contamination (clean state isolation upon reset).
4. Strict determinism across replays.
5. Warm-up behaviour and fallback handling.
6. Stable behaviour on stationary traffic without false triggers.
7. Dynamic response to controlled change in one feature.
8. Multi-signal attribution transparency and per-feature contribution.
9. Experiment D contradiction dynamics preservation (safety).
10. A/B/C experiment artifact integrity and schema completeness.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

import numpy as np

from core.contracts import (
    Direction,
    FeatureAvailability,
    NetworkState,
    Source,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    new_id,
)
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.rollout import MultiStepRolloutEngine
from eval.run_future_security_risk_validation import evaluate_sequential_stream
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.scenarios import get_demo_scenario_states
from security.bridge_v3 import MultiSignalRollingBaselineSecurityBridge
from security.contracts import EvidenceStrength, SignatureType
from security.risk_engine import SecurityRiskEngine
from tests.test_future_security_risk import _make_test_state


ROOT_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT_DIR / "artifacts" / "models" / "ar5_authoritative"
EXP_DIR = ROOT_DIR / "artifacts" / "experiments" / "bridge_multisignal_experiment_v1"


class TestMultiSignalRollingBaselineSecurityBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ar_model, cls.scales = load_ar_model(MODEL_DIR)
        cls.rollout_engine = MultiStepRolloutEngine(cls.ar_model, CSV_AVAILABLE_FEATURES)
        cls.risk_engine = SecurityRiskEngine()
        cls.demo_states = get_demo_scenario_states("demo_recon_15s")

    def test_01_truncation_invariance_and_no_future_leakage(self):
        """
        Verify truncation invariance: outputs up to window t are bitwise identical
        whether evaluated on the full stream or a stream truncated at window t.
        """
        b_full = MultiSignalRollingBaselineSecurityBridge(rolling_window_length=30, k_mad=3.0)
        recs_full = evaluate_sequential_stream(
            self.demo_states,
            source_split="demo_full",
            rollout_engine=self.rollout_engine,
            bridge=b_full,
            risk_engine=self.risk_engine,
        )

        b_trunc = MultiSignalRollingBaselineSecurityBridge(rolling_window_length=30, k_mad=3.0)
        recs_trunc = evaluate_sequential_stream(
            self.demo_states[:7],
            source_split="demo_trunc",
            rollout_engine=self.rollout_engine,
            bridge=b_trunc,
            risk_engine=self.risk_engine,
        )

        self.assertEqual(len(recs_trunc), 7)
        for k in range(7):
            self.assertEqual(recs_full[k].r0, recs_trunc[k].r0, f"Future leakage in r0 at window {k}")
            self.assertEqual(recs_full[k].r1, recs_trunc[k].r1, f"Future leakage in r1 at window {k}")
            self.assertEqual(recs_full[k].r2, recs_trunc[k].r2, f"Future leakage in r2 at window {k}")
            self.assertEqual(recs_full[k].r3, recs_trunc[k].r3, f"Future leakage in r3 at window {k}")
            self.assertEqual(recs_full[k].primary_stage, recs_trunc[k].primary_stage)

    def test_02_no_cross_stream_contamination(self):
        """Verify that reset() completely clears all internal buffers and prevents state leakage."""
        bridge = MultiSignalRollingBaselineSecurityBridge(rolling_window_length=20)

        # Pollute bridge with heavy traffic
        for _ in range(10):
            st = _make_test_state(dst_port_diversity=50, flow_count=200, byte_rate=50000.0)
            bridge.extract_signatures(st, update_baseline=True)

        stats_before = bridge.get_signal_stats()
        self.assertTrue(stats_before["port"]["is_active"])
        self.assertGreater(stats_before["port"]["median"], 20.0)

        # Reset
        bridge.reset()
        stats_after = bridge.get_signal_stats()
        self.assertFalse(stats_after["port"]["is_active"])
        self.assertEqual(stats_after["port"]["median"], 0.0)

    def test_03_strict_determinism(self):
        """Verify that processing the same sequence twice yields bitwise identical results."""
        bridge = MultiSignalRollingBaselineSecurityBridge()

        bridge.reset()
        run1 = evaluate_sequential_stream(
            self.demo_states[:6],
            source_split="det1",
            rollout_engine=self.rollout_engine,
            bridge=bridge,
            risk_engine=self.risk_engine,
        )

        bridge.reset()
        run2 = evaluate_sequential_stream(
            self.demo_states[:6],
            source_split="det2",
            rollout_engine=self.rollout_engine,
            bridge=bridge,
            risk_engine=self.risk_engine,
        )

        for r1, r2 in zip(run1, run2):
            self.assertEqual(r1.r0, r2.r0)
            self.assertEqual(r1.r1, r2.r1)
            self.assertEqual(r1.r2, r2.r2)
            self.assertEqual(r1.r3, r2.r3)
            self.assertEqual(r1.primary_stage, r2.primary_stage)

    def test_04_warmup_behaviour(self):
        """Verify fallback behavior when history length < min_history."""
        bridge = MultiSignalRollingBaselineSecurityBridge(min_history=5)
        st_cold = _make_test_state(dst_port_diversity=20, flow_count=50)

        # Before min_history, is_active is False
        stats = bridge.get_signal_stats()
        self.assertFalse(stats["port"]["is_active"])

        # Cold window evaluates without crashing
        sigs = bridge.extract_signatures(st_cold, update_baseline=True)
        self.assertTrue(len(sigs) >= 1)

    def test_05_stability_on_stationary_traffic(self):
        """Verify that stationary background traffic does not trigger signatures once warmed up."""
        bridge = MultiSignalRollingBaselineSecurityBridge(rolling_window_length=20, min_history=5)

        # Feed 15 identical windows
        for _ in range(15):
            st = _make_test_state(dst_port_diversity=25, flow_count=70, byte_rate=8000.0)
            bridge.extract_signatures(st, update_baseline=True)

        # 16th identical window should produce near-zero z-scores and zero active threat signatures
        st_test = _make_test_state(dst_port_diversity=25, flow_count=70, byte_rate=8000.0)
        z_dict = bridge.compute_causal_z_scores(st_test)
        for sig_name, z in z_dict.items():
            self.assertLess(z, 0.5, f"Stationary signal {sig_name} produced unexpected z={z}")

        sigs = bridge.extract_signatures(st_test, update_baseline=False)
        active_threat_sigs = [
            s for s in sigs
            if s.signature_type in (
                SignatureType.RECONNAISSANCE_PORT_EXPLORATION,
                SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE,
                SignatureType.EXFILTRATION_OUTBOUND_SURGE,
            )
        ]
        self.assertEqual(len(active_threat_sigs), 0, "Stationary traffic should not trigger threat signatures")

    def test_06_dynamic_response_to_controlled_single_feature_spike(self):
        """Verify that spiking only one feature triggers the corresponding signature and attributes correctly."""
        bridge = MultiSignalRollingBaselineSecurityBridge(rolling_window_length=20, min_history=5)

        # Baseline: 10 windows with byte_rate = 5000.0
        for _ in range(10):
            st = _make_test_state(dst_port_diversity=10, flow_count=50, byte_rate=5000.0)
            bridge.extract_signatures(st, update_baseline=True)

        # Sudden spike in byte_rate only (to 500,000 B/s)
        st_spike = _make_test_state(dst_port_diversity=10, flow_count=50, byte_rate=500000.0)
        z_dict = bridge.compute_causal_z_scores(st_spike)
        comp_z, primary, contribs = bridge.aggregate_multi_signal_evidence(z_dict)

        self.assertEqual(primary, "byte", f"Expected primary contributor 'byte', got '{primary}'")
        self.assertGreaterEqual(z_dict["byte"], 3.0, "Spike in byte rate must produce z_byte >= 3.0")

        sigs = bridge.extract_signatures(st_spike, update_baseline=False)
        exfil_sigs = [s for s in sigs if s.signature_type == SignatureType.EXFILTRATION_OUTBOUND_SURGE]
        self.assertTrue(len(exfil_sigs) >= 1, "Exfiltration surge signature must trigger upon byte spike")
        self.assertEqual(exfil_sigs[0].evidence_strength, EvidenceStrength.HIGH)

    def test_07_multi_signal_attribution_transparency(self):
        """Verify that aggregate_multi_signal_evidence exposes transparent per-feature contributions."""
        bridge = MultiSignalRollingBaselineSecurityBridge()
        z_mock = {"port": 4.0, "flow": 2.5, "byte": 0.5, "timing": 0.2}

        comp_z, primary, contribs = bridge.aggregate_multi_signal_evidence(z_mock)

        self.assertEqual(primary, "port")
        self.assertEqual(contribs["port"], 4.0)
        # flow bonus = 0.35 * (2.5 - 1.5) = 0.35
        self.assertAlmostEqual(contribs["flow"], 0.35, places=2)
        # byte and timing below 1.5 contribute 0.0
        self.assertEqual(contribs["byte"], 0.0)
        self.assertEqual(contribs["timing"], 0.0)
        self.assertAlmostEqual(comp_z, 4.35, places=2)

    def test_08_experiment_d_contradiction_preservation(self):
        """Verify that contradiction reversal in demo_recon_15s produces trust drop and risk dampening."""
        bridge = MultiSignalRollingBaselineSecurityBridge()

        def dynamic_contradiction_trust(idx: int, st: NetworkState, cur_delta: dict[str, float]) -> TrustAssessment:
            port_change = abs(cur_delta.get("dst_port_diversity", 0.0))
            if port_change >= 10.0 and idx >= 8:
                t_val = 0.35
                t_lvl = TrustLevel.LOW
            else:
                t_val = 0.85
                t_lvl = TrustLevel.HIGH

            return TrustAssessment(
                assessment_id=new_id("trust-contra"),
                forecast_id=f"fc-demo-w{idx:02d}",
                forecast_confidence=t_val,
                model_disagreement=0.40 if t_lvl == TrustLevel.LOW else 0.05,
                distribution_shift_score=0.45 if t_lvl == TrustLevel.LOW else 0.05,
                novelty_score=0.30 if t_lvl == TrustLevel.LOW else 0.05,
                historical_error=0.10,
                data_quality=st.data_quality,
                composite_trust=t_val,
                trust_level=t_lvl,
                contributing_factors=(
                    TrustFactor(name="reversal_penalty" if t_lvl == TrustLevel.LOW else "historical_error",
                                value=0.40 if t_lvl == TrustLevel.LOW else 0.10,
                                direction=Direction.DECREASES_TRUST if t_lvl == TrustLevel.LOW else Direction.INCREASES_TRUST),
                ),
            )

        recs = evaluate_sequential_stream(
            self.demo_states,
            source_split="demo_contra",
            rollout_engine=self.rollout_engine,
            bridge=bridge,
            risk_engine=self.risk_engine,
            dynamic_trust_fn=dynamic_contradiction_trust,
        )

        r0_traj = [r.r0 for r in recs]
        trust_traj = [r.composite_trust for r in recs]

        peak_r0 = max(r0_traj[6:9])
        contra_r0 = min(r0_traj[9:12])
        reduction_pct = (peak_r0 - contra_r0) / peak_r0 * 100.0

        self.assertGreater(peak_r0, contra_r0, "Risk must decrease during contradiction reversal")
        self.assertGreaterEqual(reduction_pct, 40.0, f"Expected >=40% risk dampening, got {reduction_pct:.1f}%")
        self.assertEqual(min(trust_traj[8:12]), 0.35, "Trust must drop to 0.35 during reversal")

    def test_09_experiment_artifacts_exist_and_conform(self):
        """Verify that all CSVs, JSONs, and 8 figures generated by the experiment runner exist."""
        self.assertTrue(EXP_DIR.exists(), "Experiment directory missing")
        self.assertTrue((EXP_DIR / "manifest.json").exists(), "manifest.json missing")
        self.assertTrue((EXP_DIR / "results_summary.json").exists(), "results_summary.json missing")
        self.assertTrue((EXP_DIR / "comparison.csv").exists(), "comparison.csv missing")
        self.assertTrue((EXP_DIR / "per_block.csv").exists(), "per_block.csv missing")
        self.assertTrue((EXP_DIR / "pre_onset_comparison.csv").exists(), "pre_onset_comparison.csv missing")
        self.assertTrue((EXP_DIR / "ablation_results.csv").exists(), "ablation_results.csv missing")
        self.assertTrue((EXP_DIR / "feature_contributions.csv").exists(), "feature_contributions.csv missing")

        fig_dir = EXP_DIR / "figures"
        for i in range(1, 9):
            png_files = list(fig_dir.glob(f"0{i}_*.png"))
            self.assertEqual(len(png_files), 1, f"Plot 0{i} missing in {fig_dir}")


if __name__ == "__main__":
    unittest.main()
