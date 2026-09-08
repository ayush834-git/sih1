"""Comprehensive unit and integration tests for DemoAdapter (SIH 26153)."""
from __future__ import annotations

import asyncio
import unittest
from pathlib import Path

from runtime.demo_adapter import (
    AdapterMessageType,
    DemoAdapter,
    DemoAdapterMessage,
    DemoStatus,
)
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.engine import LiveDemoEngine
from scenarios.demo.scenarios import get_demo_scenario_states


class DemoAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        # Load the authoritative AR(5) model
        model_dir = Path("artifacts/models/ar5_authoritative")
        ar_model, scales = load_ar_model(model_dir)
        self.engine = LiveDemoEngine(ar_model=ar_model, scales=scales)
        self.adapter = DemoAdapter(engine=self.engine, base_step_delay=0.01)

    async def asyncTearDown(self) -> None:
        await self.adapter.reset()

    async def test_initial_state_is_idle(self) -> None:
        status = self.adapter.get_status()
        self.assertEqual(status["status"], DemoStatus.IDLE.value)
        self.assertEqual(status["current_step"], -1)
        self.assertEqual(status["total_steps"], 0)
        self.assertEqual(len(self.adapter.event_history), 0)
        self.assertIsNone(self.adapter.current_event)

    async def test_start_initializes_scenario_and_steps(self) -> None:
        # Speed = 0 for manual deterministic stepping
        status = await self.adapter.start("demo_recon_15s", speed=0.0)
        self.assertEqual(status["status"], DemoStatus.RUNNING.value)
        self.assertEqual(status["scenario"], "demo_recon_15s")
        self.assertEqual(status["total_steps"], 16)
        self.assertEqual(status["current_step"], -1)

    async def test_step_advances_event_sequentially(self) -> None:
        await self.adapter.start("demo_recon_15s", speed=0.0)

        # Step 0
        evt0 = await self.adapter.step()
        self.assertIsNotNone(evt0)
        self.assertEqual(evt0.step_index, 0)
        self.assertEqual(evt0.logical_time_str, "T00 (000s)")
        self.assertEqual(self.adapter.current_step, 0)
        self.assertEqual(len(self.adapter.event_history), 1)

        # Step 1
        evt1 = await self.adapter.step()
        self.assertIsNotNone(evt1)
        self.assertEqual(evt1.step_index, 1)
        self.assertEqual(evt1.logical_time_str, "T01 (010s)")
        self.assertEqual(self.adapter.current_step, 1)
        self.assertEqual(len(self.adapter.event_history), 2)

    async def test_event_contains_real_pipeline_and_explainability(self) -> None:
        await self.adapter.start("demo_recon_15s", speed=0.0)

        # Advance to T07 (Reconnaissance attack in progress)
        for _ in range(8):
            evt = await self.adapter.step()

        self.assertIsNotNone(evt)
        self.assertEqual(evt.step_index, 7)
        self.assertEqual(evt.primary_stage, "Reconnaissance")
        self.assertGreater(len(evt.active_signatures), 0)

        # Verify explainability fields from Phase 1 are intact
        self.assertIsInstance(evt.forecast_feature_contributions, list)
        self.assertGreater(len(evt.forecast_feature_contributions), 0)
        self.assertIsInstance(evt.security_explanation, dict)
        self.assertEqual(evt.security_explanation.get("primary_stage"), "Reconnaissance")

    async def test_pause_and_resume(self) -> None:
        await self.adapter.start("demo_recon_15s", speed=0.0)
        await self.adapter.step()  # step 0
        await self.adapter.step()  # step 1

        pause_status = await self.adapter.pause()
        self.assertEqual(pause_status["status"], DemoStatus.PAUSED.value)
        self.assertEqual(self.adapter.current_step, 1)

        # Manual step while paused preserves position and advances
        evt2 = await self.adapter.step()
        self.assertEqual(evt2.step_index, 2)
        self.assertEqual(self.adapter.current_step, 2)

        resume_status = await self.adapter.resume()
        self.assertEqual(resume_status["status"], DemoStatus.RUNNING.value)
        self.assertEqual(self.adapter.current_step, 2)

    async def test_reset_clears_all_state(self) -> None:
        await self.adapter.start("demo_recon_15s", speed=0.0)
        await self.adapter.step()
        await self.adapter.step()
        self.assertEqual(len(self.adapter.event_history), 2)

        reset_status = await self.adapter.reset()
        self.assertEqual(reset_status["status"], DemoStatus.IDLE.value)
        self.assertEqual(self.adapter.current_step, -1)
        self.assertEqual(self.adapter.total_steps, 0)
        self.assertEqual(len(self.adapter.event_history), 0)
        self.assertIsNone(self.adapter.current_event)
        self.assertIsNone(self.adapter.scenario)

    async def test_completion_when_scenario_exhausts(self) -> None:
        await self.adapter.start("demo_recon_15s", speed=0.0)
        total_steps = self.adapter.total_steps
        self.assertEqual(total_steps, 16)

        for i in range(total_steps):
            evt = await self.adapter.step()
            self.assertIsNotNone(evt)
            self.assertEqual(evt.step_index, i)

        self.assertEqual(self.adapter.status, DemoStatus.COMPLETED)
        self.assertEqual(self.adapter.current_step, 15)

        # Stepping after completion returns None safely
        over_step = await self.adapter.step()
        self.assertIsNone(over_step)
        self.assertEqual(self.adapter.status, DemoStatus.COMPLETED)

    async def test_repeated_start_protection(self) -> None:
        await self.adapter.start("demo_recon_15s", speed=0.0)
        await self.adapter.step()
        self.assertEqual(self.adapter.current_step, 0)

        # Calling start again while running restarts cleanly without duplicate task
        await self.adapter.start("demo_dos", speed=0.0)
        self.assertEqual(self.adapter.scenario, "demo_dos")
        self.assertEqual(self.adapter.total_steps, 10)
        self.assertEqual(self.adapter.current_step, -1)
        self.assertEqual(len(self.adapter.event_history), 0)

    async def test_repeated_pause_and_resume_protection(self) -> None:
        await self.adapter.start("demo_recon_15s", speed=0.0)

        # Pause twice
        await self.adapter.pause()
        p2 = await self.adapter.pause()
        self.assertEqual(p2["status"], DemoStatus.PAUSED.value)

        # Resume twice
        await self.adapter.resume()
        r2 = await self.adapter.resume()
        self.assertEqual(r2["status"], DemoStatus.RUNNING.value)

    async def test_invalid_state_transitions_raise(self) -> None:
        # Pause before start raises
        with self.assertRaises(RuntimeError):
            await self.adapter.pause()

        # Resume before start raises
        with self.assertRaises(RuntimeError):
            await self.adapter.resume()

        # Step before start raises
        with self.assertRaises(RuntimeError):
            await self.adapter.step()

    async def test_invalid_scenario_validation(self) -> None:
        with self.assertRaises(ValueError):
            await self.adapter.start("non_existent_scenario_xyz")

    async def test_subscriber_receives_status_events_and_completion(self) -> None:
        received_messages: list[DemoAdapterMessage] = []

        async def subscriber_worker():
            async for msg in self.adapter.subscribe():
                received_messages.append(msg)
                if msg.message_type == AdapterMessageType.COMPLETED:
                    break

        sub_task = asyncio.create_task(subscriber_worker())
        await asyncio.sleep(0.01)

        # Start and step 16 times
        await self.adapter.start("demo_recon_15s", speed=0.0)
        for _ in range(16):
            await self.adapter.step()

        await asyncio.wait_for(sub_task, timeout=2.0)

        # Check received messages
        types = [m.message_type for m in received_messages]
        self.assertIn(AdapterMessageType.STATUS, types)
        self.assertIn(AdapterMessageType.EVENT, types)
        self.assertIn(AdapterMessageType.COMPLETED, types)

        # 1 status on start + 16 events + 1 completion
        event_msgs = [m for m in received_messages if m.message_type == AdapterMessageType.EVENT]
        self.assertEqual(len(event_msgs), 16)
        self.assertEqual(event_msgs[0].step_index, 0)
        self.assertEqual(event_msgs[-1].step_index, 15)

    async def test_automated_timer_playback(self) -> None:
        # Test automated playback at high speed with fast delay
        fast_adapter = DemoAdapter(engine=self.engine, base_step_delay=0.005)
        await fast_adapter.start("demo_recon_15s", speed=10.0)

        # Wait for auto-stepping to complete
        for _ in range(100):
            if fast_adapter.status == DemoStatus.COMPLETED:
                break
            await asyncio.sleep(0.01)

        self.assertEqual(fast_adapter.status, DemoStatus.COMPLETED)
        self.assertEqual(len(fast_adapter.event_history), 16)
        self.assertEqual(fast_adapter.current_step, 15)
        await fast_adapter.reset()

    async def test_all_5_scenarios_execute_through_adapter(self) -> None:
        scenarios = [
            ("demo_recon_15s", 16),
            ("demo_recon", 10),
            ("demo_dos", 10),
            ("demo_exfiltration", 10),
            ("demo_ambiguous", 10),
        ]

        for sc_name, expected_steps in scenarios:
            await self.adapter.start(sc_name, speed=0.0)
            self.assertEqual(self.adapter.total_steps, expected_steps)
            for i in range(expected_steps):
                evt = await self.adapter.step()
                self.assertIsNotNone(evt)
                self.assertEqual(evt.step_index, i)
            self.assertEqual(self.adapter.status, DemoStatus.COMPLETED)
            await self.adapter.reset()


if __name__ == "__main__":
    unittest.main()
