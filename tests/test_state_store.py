"""Comprehensive tests for RuntimeStateStore and its DemoAdapter integration (SIH 26153)."""
from __future__ import annotations

import asyncio
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from runtime.demo_adapter import DemoAdapter
from runtime.state_store import DemoStatus, RuntimeSnapshot, RuntimeStateStore
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.engine import DemoEvent, LiveDemoEngine
from scenarios.demo.scenarios import get_demo_scenario_states


def make_dummy_event(step_index: int) -> DemoEvent:
    """Create a minimal schema-compliant DemoEvent for state store testing."""
    return DemoEvent(
        event_id=f"evt-{step_index:04d}-test",
        step_index=step_index,
        logical_time_str=f"T{step_index:02d} ({step_index * 10:03d}s)",
        wall_clock_time=datetime.now(),
        current_state_summary={"flow_count": 10.0 + step_index},
        predicted_deltas_h1={"flow_count_delta": 1.0},
        primary_stage="Reconnaissance" if step_index > 3 else "Unknown",
        stage_confidence=0.85,
        trust_level="HIGH",
        composite_trust=0.85,
        priority_level="LOW",
        composite_priority=0.2,
        active_signatures=["TEST_SIG"],
        candidate_attack_techniques=["T1046"],
        relevant_roles=["SOC_ANALYST"],
        omitted_roles=[],
        dispatched_notifications=[],
        recommended_strategy="MONITOR",
        requires_human=False,
        is_reversible=True,
        recommended_actions=[],
        explanation="Test explanation",
    )


class StateStoreUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = RuntimeStateStore(max_history_size=10)

    def test_1_initial_idle_state(self) -> None:
        self.assertEqual(self.store.status, DemoStatus.IDLE)
        self.assertIsNone(self.store.session_id)
        self.assertIsNone(self.store.scenario)
        self.assertEqual(self.store.current_step, -1)
        self.assertEqual(self.store.total_steps, 0)
        self.assertIsNone(self.store.current_event)
        self.assertEqual(len(self.store.get_event_history()), 0)

        snapshot = self.store.get_snapshot()
        self.assertEqual(snapshot.status, DemoStatus.IDLE)
        self.assertEqual(snapshot.history_count, 0)

    def test_2_session_creation(self) -> None:
        snap = self.store.create_session("demo_recon_15s", total_steps=16)
        self.assertEqual(self.store.status, DemoStatus.RUNNING)
        self.assertEqual(self.store.scenario, "demo_recon_15s")
        self.assertEqual(self.store.total_steps, 16)
        self.assertEqual(self.store.current_step, -1)
        self.assertTrue(self.store.session_id.startswith("sess-"))
        self.assertEqual(snap.session_id, self.store.session_id)

    def test_3_append_event_and_current_event(self) -> None:
        self.store.create_session("demo_recon_15s", total_steps=16)
        evt0 = make_dummy_event(0)
        self.store.append_event(evt0)

        self.assertEqual(self.store.current_step, 0)
        self.assertEqual(self.store.current_event, evt0)
        self.assertEqual(len(self.store.get_event_history()), 1)
        self.assertEqual(self.store.get_event(0), evt0)

        evt1 = make_dummy_event(1)
        self.store.append_event(evt1)
        self.assertEqual(self.store.current_step, 1)
        self.assertEqual(self.store.current_event, evt1)
        self.assertEqual(len(self.store.get_event_history()), 2)
        self.assertEqual(self.store.get_event(1), evt1)

    def test_4_ordered_history_and_filtering(self) -> None:
        self.store.create_session("demo_recon_15s", total_steps=10)
        for i in range(5):
            self.store.append_event(make_dummy_event(i))

        history = self.store.get_event_history()
        self.assertEqual(len(history), 5)
        for idx, evt in enumerate(history):
            self.assertEqual(evt.step_index, idx)

        # Filter since step 2
        filtered = self.store.get_event_history(since_step=2)
        self.assertEqual(len(filtered), 3)
        self.assertEqual(filtered[0].step_index, 2)
        self.assertEqual(filtered[-1].step_index, 4)

        # Limit to 2 items
        limited = self.store.get_event_history(limit=2)
        self.assertEqual(len(limited), 2)
        self.assertEqual(limited[0].step_index, 3)
        self.assertEqual(limited[1].step_index, 4)

    def test_5_history_limit_and_oldest_eviction(self) -> None:
        small_store = RuntimeStateStore(max_history_size=3)
        small_store.create_session("demo_dos", total_steps=10)

        small_store.append_event(make_dummy_event(0))
        small_store.append_event(make_dummy_event(1))
        small_store.append_event(make_dummy_event(2))
        self.assertEqual(len(small_store.get_event_history()), 3)

        # Append 4th event -> oldest (0) should be evicted
        small_store.append_event(make_dummy_event(3))
        history = small_store.get_event_history()
        self.assertEqual(len(history), 3)
        self.assertEqual(history[0].step_index, 1)
        self.assertEqual(history[1].step_index, 2)
        self.assertEqual(history[2].step_index, 3)
        self.assertIsNone(small_store.get_event(0))  # Evicted

    def test_6_reset_clears_all_state(self) -> None:
        self.store.create_session("demo_recon_15s", total_steps=5)
        self.store.append_event(make_dummy_event(0))
        self.store.append_event(make_dummy_event(1))

        self.store.reset()
        self.assertEqual(self.store.status, DemoStatus.IDLE)
        self.assertIsNone(self.store.session_id)
        self.assertIsNone(self.store.scenario)
        self.assertEqual(self.store.current_step, -1)
        self.assertEqual(self.store.total_steps, 0)
        self.assertIsNone(self.store.current_event)
        self.assertEqual(len(self.store.get_event_history()), 0)

    def test_7_status_transitions(self) -> None:
        self.store.create_session("demo_recon_15s", total_steps=5)
        self.assertEqual(self.store.status, DemoStatus.RUNNING)

        self.store.set_status(DemoStatus.PAUSED)
        self.assertEqual(self.store.status, DemoStatus.PAUSED)

        self.store.set_status("RUNNING")
        self.assertEqual(self.store.status, DemoStatus.RUNNING)

        self.store.set_status(DemoStatus.COMPLETED)
        self.assertEqual(self.store.status, DemoStatus.COMPLETED)

    def test_8_session_id_uniqueness(self) -> None:
        self.store.create_session("demo_recon_15s", total_steps=5)
        s1 = self.store.session_id

        self.store.create_session("demo_dos", total_steps=5)
        s2 = self.store.session_id

        self.assertNotEqual(s1, s2)

    def test_9_invalid_step_rejection(self) -> None:
        self.store.create_session("demo_recon_15s", total_steps=5)

        # Expected step 0, got step 3 -> ValueError
        with self.assertRaises(ValueError):
            self.store.append_event(make_dummy_event(3))

        # Append step 0
        self.store.append_event(make_dummy_event(0))

        # Expected step 1, got step 0 (duplicate) -> ValueError
        with self.assertRaises(ValueError):
            self.store.append_event(make_dummy_event(0))

        # Expected step 1, got step 2 (gap) -> ValueError
        with self.assertRaises(ValueError):
            self.store.append_event(make_dummy_event(2))

    def test_10_append_without_session_raises(self) -> None:
        # Store is in IDLE state
        with self.assertRaises(RuntimeError):
            self.store.append_event(make_dummy_event(0))

    def test_11_concurrent_append_and_read_safety(self) -> None:
        self.store.create_session("demo_recon_15s", total_steps=200)

        def reader():
            for _ in range(100):
                _ = self.store.get_snapshot()
                _ = self.store.get_event_history(limit=5)
                _ = self.store.get_current_event()

        def writer():
            for i in range(100):
                self.store.append_event(make_dummy_event(i))

        with ThreadPoolExecutor(max_workers=4) as executor:
            f_w = executor.submit(writer)
            f_r1 = executor.submit(reader)
            f_r2 = executor.submit(reader)
            f_w.result()
            f_r1.result()
            f_r2.result()

        self.assertEqual(self.store.current_step, 99)
        self.assertEqual(len(self.store.get_event_history()), 10)  # Bounded to 10


class DemoAdapterStoreIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        model_dir = Path("artifacts/models/ar5_authoritative")
        ar_model, scales = load_ar_model(model_dir)
        self.engine = LiveDemoEngine(ar_model=ar_model, scales=scales)
        self.store = RuntimeStateStore(max_history_size=500)
        self.adapter = DemoAdapter(engine=self.engine, store=self.store, base_step_delay=0.01)

    async def asyncTearDown(self) -> None:
        await self.adapter.reset()

    async def test_adapter_and_store_have_single_state_source(self) -> None:
        self.assertIs(self.adapter.store, self.store)
        self.assertEqual(self.adapter.status, self.store.status)

        await self.adapter.start("demo_recon_15s", speed=0.0)
        self.assertEqual(self.adapter.status, DemoStatus.RUNNING)
        self.assertEqual(self.store.status, DemoStatus.RUNNING)
        self.assertEqual(self.adapter.session_id, self.store.session_id)
        self.assertEqual(self.adapter.total_steps, 16)
        self.assertEqual(self.store.total_steps, 16)

        # Step 0
        evt0 = await self.adapter.step()
        self.assertIsNotNone(evt0)
        self.assertEqual(self.adapter.current_step, 0)
        self.assertEqual(self.store.current_step, 0)
        self.assertEqual(self.adapter.current_event, evt0)
        self.assertEqual(self.store.current_event, evt0)
        self.assertEqual(self.adapter.event_history, self.store.get_event_history())

        # Step remaining 15 steps
        for _ in range(15):
            await self.adapter.step()

        self.assertEqual(self.adapter.status, DemoStatus.COMPLETED)
        self.assertEqual(self.store.status, DemoStatus.COMPLETED)
        self.assertEqual(len(self.adapter.event_history), 16)
        self.assertEqual(len(self.store.get_event_history()), 16)

    async def test_snapshot_representation(self) -> None:
        await self.adapter.start("demo_recon_15s", speed=0.0)
        await self.adapter.step()
        await self.adapter.step()

        snapshot = self.adapter.get_snapshot()
        self.assertIsInstance(snapshot, RuntimeSnapshot)
        self.assertEqual(snapshot.scenario, "demo_recon_15s")
        self.assertEqual(snapshot.current_step, 1)
        self.assertEqual(snapshot.total_steps, 16)
        self.assertEqual(snapshot.history_count, 2)
        self.assertIsNotNone(snapshot.current_event)

        d = snapshot.to_dict()
        self.assertEqual(d["scenario"], "demo_recon_15s")
        self.assertEqual(d["current_step"], 1)
        self.assertEqual(d["status"], "RUNNING")
        self.assertIsInstance(d["current_event"], dict)


if __name__ == "__main__":
    unittest.main()
