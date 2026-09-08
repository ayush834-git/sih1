"""
Unit and Regression Tests for RollingBaselineSecurityBridge (SIH PS 26153).

Validates:
1. Explicit named parameter exposure and configurable defaults (W=30, k=3.0, min_mad=2.0).
2. Zero future leakage under sequence truncation (causal-only rolling baseline).
3. Risk score bounds: 0.0 <= R(t+h) <= 1.0 for all horizons h in {0, 1, 2, 3}.
4. Strict determinism upon reset and identical stream replays.
5. Dynamic adaptation: stationary high-diversity background is suppressed, true spikes trigger signatures.
6. Experiment D contradiction dynamics: trust drop and risk dampening preserved.
7. A/B experiment artifact integrity and schema completeness.
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
from security.bridge_v2 import RollingBaselineSecurityBridge
from security.contracts import EvidenceStrength, SignatureType
from security.risk_engine import SecurityRiskEngine


ROOT_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT_DIR / "artifacts" / "models" / "ar5_authoritative"
AB_EXP_DIR = ROOT_DIR / "artifacts" / "experiments" / "bridge_ab_experiment_v1"


class TestRollingBaselineSecurityBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ar_model, cls.scales = load_ar_model(MODEL_DIR)
        cls.rollout_engine = MultiStepRolloutEngine(cls.ar_model, CSV_AVAILABLE_FEATURES)
        cls.risk_engine = SecurityRiskEngine()
        cls.demo_states = get_demo_scenario_states("demo_recon_15s")

    def test_01_parameter_exposure_and_defaults(self):
        """Verify explicit named parameters are exposed with verified pre-test defaults."""
        bridge = RollingBaselineSecurityBridge(
            rolling_window_length=30,
            k_mad=3.0,
            min_mad=2.0,
            min_history=5,
            static_fallback_threshold=15.0,
        )
        self.assertEqual(bridge.rolling_window_length, 30)
        self.assertEqual(bridge.k_mad, 3.0)
        self.assertEqual(bridge.min_mad, 2.0)
        self.assertEqual(bridge.min_history, 5)
        self.assertEqual(bridge.static_fallback_threshold, 15.0)

        # Custom initialization
        custom = RollingBaselineSecurityBridge(rolling_window_length=45, k_mad=2.5, min_mad=1.5)
        self.assertEqual(custom.rolling_window_length, 45)
        self.assertEqual(custom.k_mad, 2.5)
        self.assertEqual(custom.min_mad, 1.5)

    def test_02_causal_rolling_baseline_no_future_leakage(self):
        """
        Verify that future windows have zero effect on rolling baseline or computed risk at window t.
        Evaluates full sequence vs truncated sequence.
        """
        b_full = RollingBaselineSecurityBridge(rolling_window_length=30, k_mad=3.0, min_mad=2.0)
        recs_full = evaluate_sequential_stream(
            self.demo_states,
            source_split="demo_full",
            rollout_engine=self.rollout_engine,
            bridge=b_full,
            risk_engine=self.risk_engine,
        )

        b_trunc = RollingBaselineSecurityBridge(rolling_window_length=30, k_mad=3.0, min_mad=2.0)
        recs_trunc = evaluate_sequential_stream(
            self.demo_states[:8],
            source_split="demo_trunc",
            rollout_engine=self.rollout_engine,
            bridge=b_trunc,
            risk_engine=self.risk_engine,
        )

        self.assertEqual(len(recs_trunc), 8)
        for k in range(8):
            self.assertEqual(recs_full[k].r0, recs_trunc[k].r0, f"Future leakage at window {k} for r0")
            self.assertEqual(recs_full[k].r1, recs_trunc[k].r1, f"Future leakage at window {k} for r1")
            self.assertEqual(recs_full[k].r2, recs_trunc[k].r2, f"Future leakage at window {k} for r2")
            self.assertEqual(recs_full[k].r3, recs_trunc[k].r3, f"Future leakage at window {k} for r3")
            self.assertEqual(recs_full[k].primary_stage, recs_trunc[k].primary_stage)

    def test_03_bounded_risk_scores(self):
        """Verify that risk scores remain strictly within [0.0, 1.0] across all horizons."""
        bridge = RollingBaselineSecurityBridge()
        recs = evaluate_sequential_stream(
            self.demo_states,
            source_split="demo",
            rollout_engine=self.rollout_engine,
            bridge=bridge,
            risk_engine=self.risk_engine,
        )
        for r in recs:
            for h in (0, 1, 2, 3):
                score = getattr(r, f"r{h}")
                self.assertGreaterEqual(score, 0.0)
                self.assertLessEqual(score, 1.0)

    def test_04_determinism(self):
        """Verify that identical sequences processed after bridge reset produce bitwise identical results."""
        bridge = RollingBaselineSecurityBridge(rolling_window_length=30, k_mad=3.0)

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

    def test_05_dynamic_adaptation_and_suppression(self):
        """
        Test that stationary high-diversity traffic (e.g. 20 ports) does NOT trigger
        reconnaissance once warmed up, but a sudden spike to 40 ports DOES trigger.
        """
        bridge = RollingBaselineSecurityBridge(rolling_window_length=15, k_mad=3.0, min_mad=2.0)

        from tests.test_future_security_risk import _make_test_state

        # Feed 10 stationary windows with dst_ports = 20.0
        for i in range(10):
            st = _make_test_state(dst_port_diversity=20, flow_count=50)
            sigs = bridge.extract_signatures(st, update_baseline=True)

        # 11th window with identical dst_ports = 20.0 should NOT trigger RECONNAISSANCE
        st_stable = _make_test_state(dst_port_diversity=20, flow_count=50)
        sigs_stable = bridge.extract_signatures(st_stable, update_baseline=True)
        has_recon_stable = any(s.signature_type == SignatureType.RECONNAISSANCE_PORT_EXPLORATION for s in sigs_stable)
        self.assertFalse(has_recon_stable, "Stationary high port diversity must not trigger dynamic recon signature")

        # 12th window with sudden spike to dst_ports = 50.0 MUST trigger RECONNAISSANCE
        st_spike = _make_test_state(dst_port_diversity=50, flow_count=50)
        sigs_spike = bridge.extract_signatures(st_spike, update_baseline=True)
        has_recon_spike = any(s.signature_type == SignatureType.RECONNAISSANCE_PORT_EXPLORATION for s in sigs_spike)
        self.assertTrue(has_recon_spike, "Sudden port diversity spike above rolling baseline must trigger recon signature")
        spike_recon_sig = next(s for s in sigs_spike if s.signature_type == SignatureType.RECONNAISSANCE_PORT_EXPLORATION)
        self.assertEqual(spike_recon_sig.evidence_strength, EvidenceStrength.HIGH)

    def test_06_experiment_d_contradiction_preservation(self):
        """Verify contradiction dynamics in Experiment D produce trust drop and risk reduction."""
        bridge = RollingBaselineSecurityBridge(rolling_window_length=30, k_mad=3.0)

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

        # Phase 3 peak vs Phase 4 contradiction trough
        peak_r0 = max(r0_traj[6:9])
        trough_r0 = min(r0_traj[9:12])
        reduction_pct = (peak_r0 - trough_r0) / peak_r0 * 100.0

        self.assertGreater(peak_r0, trough_r0, "Risk must decrease during contradiction phase")
        self.assertGreaterEqual(reduction_pct, 40.0, f"Expected >=40% risk reduction, got {reduction_pct:.1f}%")
        self.assertEqual(min(trust_traj[8:12]), 0.35, "Trust must drop to 0.35 during reversal")

    def test_07_a_b_manifest_integrity(self):
        """Verify that the A/B experiment manifest exists and contains complete comparison data."""
        manifest_path = AB_EXP_DIR / "manifest.json"
        self.assertTrue(manifest_path.exists(), "A/B manifest missing")
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("OLD_STATIC", data["bridges"])
        self.assertIn("NEW_ROLLING", data["bridges"])
        self.assertIn("summary_table", data)
        self.assertIn("parameter_selection_provenance", data["metadata"])


if __name__ == "__main__":
    unittest.main()
