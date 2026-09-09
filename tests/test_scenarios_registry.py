"""Unit and integration tests for Scenario Registry & Multi-Scenario Replay (SIH 26153)."""
import unittest
from datetime import datetime
from pathlib import Path

from core.contracts import NetworkState
from scenarios.demo.scenarios import (
    SCENARIO_REGISTRY,
    SCENARIO_ALIASES,
    ScenarioMetadata,
    get_all_scenarios,
    get_scenario_metadata,
    get_demo_scenario_states,
)
from runtime.demo_adapter import DemoAdapter
from runtime.state_store import DemoStatus
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.engine import LiveDemoEngine
from core.topology.builder import build_enterprise_demo_topology


class ScenarioRegistryTests(unittest.IsolatedAsyncioTestCase):
    """Verify Scenario Registry integrity and multi-scenario lifecycle."""

    @classmethod
    def setUpClass(cls):
        model_dir = Path("artifacts/models/ar5_authoritative")
        cls.ar_model, cls.scales = load_ar_model(model_dir)
        cls.topology = build_enterprise_demo_topology()

    def test_01_all_registered_scenarios_exist_and_load(self):
        """All registered scenarios must load schema-compliant 18-step NetworkState sequences."""
        scenarios = get_all_scenarios()
        self.assertGreaterEqual(len(scenarios), 4, "Must register at least 4 scenarios")

        expected_ids = {
            "scenario_recon",
            "scenario_dos_flooding",
            "scenario_volumetric_surge",
            "scenario_safety_boundary",
        }
        registered_ids = {s.scenario_id for s in scenarios}
        self.assertTrue(expected_ids.issubset(registered_ids), f"Missing scenario IDs: {expected_ids - registered_ids}")

        for sc in scenarios:
            states = get_demo_scenario_states(sc.scenario_id)
            self.assertEqual(len(states), 18, f"Scenario {sc.scenario_id} must have exactly 18 steps")
            for idx, st in enumerate(states):
                self.assertIsInstance(st, NetworkState)
                self.assertFalse(st.is_empty)
                self.assertGreater(st.data_quality, 0.0)
                self.assertEqual(st.window_duration_s, 10.0)

    def test_02_backward_compatibility_alias(self):
        """demo_golden_attack must resolve seamlessly to scenario_dos_flooding."""
        meta = get_scenario_metadata("demo_golden_attack")
        self.assertEqual(meta.scenario_id, "scenario_dos_flooding")

        states_alias = get_demo_scenario_states("demo_golden_attack")
        states_canonical = get_demo_scenario_states("scenario_dos_flooding")
        self.assertEqual(len(states_alias), len(states_canonical))
        for s_a, s_c in zip(states_alias, states_canonical):
            self.assertEqual(s_a.flow_count, s_c.flow_count)
            self.assertEqual(s_a.byte_rate, s_c.byte_rate)
            self.assertEqual(s_a.dst_port_diversity, s_c.dst_port_diversity)

    def test_03_invalid_scenario_fails_closed(self):
        """Requesting an unknown scenario must fail closed with ValueError."""
        with self.assertRaises(ValueError):
            get_scenario_metadata("non_existent_attack_scenario")

        with self.assertRaises(ValueError):
            get_demo_scenario_states("non_existent_attack_scenario")

    def test_04_scenarios_have_distinct_trajectories(self):
        """Each scenario must have distinct behavioral metrics across its 18 steps."""
        s_recon = get_demo_scenario_states("scenario_recon")
        s_dos = get_demo_scenario_states("scenario_dos_flooding")
        s_vol = get_demo_scenario_states("scenario_volumetric_surge")
        s_sat = get_demo_scenario_states("scenario_safety_boundary")

        # Peak port diversity in recon vs dos
        max_pd_recon = max(s.dst_port_diversity for s in s_recon)
        max_pd_dos = max(s.dst_port_diversity for s in s_dos)
        self.assertGreater(max_pd_recon, max_pd_dos)

        # Peak byte rate in volumetric vs dos
        max_br_vol = max(s.byte_rate for s in s_vol)
        max_br_dos = max(s.byte_rate for s in s_dos)
        self.assertGreater(max_br_vol, max_br_dos)

        # Peak flow count in saturation vs recon
        max_fc_sat = max(s.flow_count for s in s_sat)
        max_fc_recon = max(s.flow_count for s in s_recon)
        self.assertGreater(max_fc_sat, max_fc_recon)

    def test_05_deterministic_repeatability(self):
        """Repeated generation of scenarios must produce byte-identical states."""
        for sc_id in ["scenario_recon", "scenario_dos_flooding", "scenario_volumetric_surge", "scenario_safety_boundary"]:
            run1 = get_demo_scenario_states(sc_id)
            run2 = get_demo_scenario_states(sc_id)
            for s1, s2 in zip(run1, run2):
                self.assertEqual(s1.feature_values(), s2.feature_values())
                self.assertEqual(s1.window_id, s2.window_id)

    async def test_06_adapter_loads_each_scenario_cleanly(self):
        """DemoAdapter must start, step, and reset each registered scenario cleanly."""
        for sc_id in ["scenario_recon", "scenario_dos_flooding", "scenario_volumetric_surge", "scenario_safety_boundary"]:
            engine = LiveDemoEngine(ar_model=self.ar_model, scales=self.scales, topology=self.topology)
            adapter = DemoAdapter(engine=engine)
            self.assertEqual(adapter.status, DemoStatus.IDLE)

            start_info = await adapter.start(scenario=sc_id, speed=0.0)
            self.assertEqual(start_info["status"], "RUNNING")
            self.assertEqual(start_info["scenario"], sc_id)
            self.assertEqual(start_info["total_steps"], 18)

            # Step through 3 steps
            for expected_step in range(3):
                ev = await adapter.step()
                self.assertIsNotNone(ev)
                self.assertEqual(ev.step_index, expected_step)

            # Reset clears state
            reset_info = await adapter.reset()
            self.assertEqual(reset_info["status"], "IDLE")
            self.assertEqual(adapter.current_step, -1)
            self.assertIsNone(adapter.current_event)

    async def test_07_switching_scenario_after_reset_has_no_stale_state(self):
        """Switching scenarios after reset must start completely clean without cross-contamination."""
        engine = LiveDemoEngine(ar_model=self.ar_model, scales=self.scales, topology=self.topology)
        adapter = DemoAdapter(engine=engine)

        # Run recon for 5 steps
        await adapter.start(scenario="scenario_recon", speed=0.0)
        for _ in range(5):
            await adapter.step()
        self.assertEqual(adapter.current_step, 4)

        # Reset
        await adapter.reset()
        self.assertEqual(adapter.status, DemoStatus.IDLE)
        self.assertEqual(len(adapter.event_history), 0)

        # Start volumetric surge
        await adapter.start(scenario="scenario_volumetric_surge", speed=0.0)
        self.assertEqual(adapter.scenario, "scenario_volumetric_surge")
        ev0 = await adapter.step()
        self.assertEqual(ev0.step_index, 0)
        self.assertEqual(len(adapter.event_history), 1)

        # Verify values belong to volumetric surge, not recon
        self.assertEqual(ev0.current_state_summary["byte_rate"], 3000.0)


if __name__ == "__main__":
    unittest.main()
