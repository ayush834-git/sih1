"""Comprehensive unit and integration tests for Server-Sent Events (SSE) streaming (SIH 26153)."""
from __future__ import annotations

import asyncio
import json
import unittest
from pathlib import Path
from typing import Any, AsyncGenerator

from runtime.api import create_app, format_sse
from runtime.demo_adapter import AdapterMessageType, DemoAdapter, DemoAdapterMessage
from runtime.state_store import DemoStatus, RuntimeStateStore
from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.engine import LiveDemoEngine


def parse_sse_frames(raw_text: str) -> list[dict[str, Any]]:
    """Parse raw SSE text into structured event dictionaries."""
    events: list[dict[str, Any]] = []
    current_event: dict[str, Any] = {}
    current_data_lines: list[str] = []

    for line in raw_text.splitlines():
        line_clean = line.strip()
        if not line_clean:
            if current_data_lines or current_event:
                if current_data_lines:
                    data_joined = "\n".join(current_data_lines)
                    try:
                        current_event["data"] = json.loads(data_joined)
                    except Exception:
                        current_event["data"] = data_joined
                events.append(current_event)
                current_event = {}
                current_data_lines = []
            continue

        if line_clean.startswith("event:"):
            current_event["event"] = line_clean[len("event:"):].strip()
        elif line_clean.startswith("id:"):
            current_event["id"] = line_clean[len("id:"):].strip()
        elif line_clean.startswith("retry:"):
            current_event["retry"] = line_clean[len("retry:"):].strip()
        elif line_clean.startswith("data:"):
            current_data_lines.append(line_clean[len("data:"):].strip())

    if current_data_lines or current_event:
        if current_data_lines:
            data_joined = "\n".join(current_data_lines)
            try:
                current_event["data"] = json.loads(data_joined)
            except Exception:
                current_event["data"] = data_joined
        events.append(current_event)

    return events


async def simulate_sse_stream(
    adapter: DemoAdapter,
    last_event_id: str | None = None,
    max_events: int = 100,
    timeout: float = 2.0,
) -> list[dict[str, Any]]:
    """Simulate the SSE route event_generator logic directly in asyncio loop."""
    frames: list[dict[str, Any]] = []

    # 1. Retry frame
    frames.extend(parse_sse_frames(format_sse(data="", retry=3000)))

    # 2. Replay missed events
    if last_event_id is not None:
        try:
            last_step = int(last_event_id)
            missed = adapter.store.get_event_history(since_step=last_step + 1)
            for evt in missed:
                f_str = format_sse(data=evt.to_dict(), event="state", event_id=evt.step_index)
                frames.extend(parse_sse_frames(f_str))
        except (ValueError, TypeError):
            pass

    # 3. Live events
    subscription = adapter.subscribe()
    sub_iter = subscription.__aiter__()

    try:
        while len(frames) < max_events:
            try:
                msg: DemoAdapterMessage = await asyncio.wait_for(sub_iter.__anext__(), timeout=timeout)
                if msg.message_type == AdapterMessageType.EVENT:
                    step_idx = msg.step_index if msg.step_index is not None else -1
                    f_str = format_sse(data=msg.data, event="state", event_id=step_idx)
                    frames.extend(parse_sse_frames(f_str))
                elif msg.message_type == AdapterMessageType.STATUS:
                    f_str = format_sse(data=msg.data, event="demo_status")
                    frames.extend(parse_sse_frames(f_str))
                elif msg.message_type == AdapterMessageType.COMPLETED:
                    f_str = format_sse(data=msg.data, event="complete")
                    frames.extend(parse_sse_frames(f_str))
                    break
                elif msg.message_type == AdapterMessageType.ERROR:
                    f_str = format_sse(data=msg.data, event="error")
                    frames.extend(parse_sse_frames(f_str))
            except asyncio.TimeoutError:
                break
            except StopAsyncIteration:
                break
    finally:
        pass

    return frames


class SseStreamTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        model_dir = Path("artifacts/models/ar5_authoritative")
        ar_model, scales = load_ar_model(model_dir)
        self.engine = LiveDemoEngine(ar_model=ar_model, scales=scales)
        self.store = RuntimeStateStore(max_history_size=500)
        self.adapter = DemoAdapter(engine=self.engine, store=self.store, base_step_delay=0.005)
        self.app = create_app(adapter=self.adapter)

    async def asyncTearDown(self) -> None:
        await self.adapter.reset()

    async def test_1_sse_format_helper(self) -> None:
        frame = format_sse(data={"step": 5}, event="state", event_id=5, retry=3000)
        self.assertIn("retry: 3000\n", frame)
        self.assertIn("event: state\n", frame)
        self.assertIn("id: 5\n", frame)
        self.assertIn('data: {"step": 5}\n\n', frame)

        parsed = parse_sse_frames(frame)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["event"], "state")
        self.assertEqual(parsed[0]["id"], "5")
        self.assertEqual(parsed[0]["retry"], "3000")
        self.assertEqual(parsed[0]["data"]["step"], 5)

    async def test_2_sse_stream_receives_state_and_demo_status(self) -> None:
        async def subscriber():
            return await simulate_sse_stream(self.adapter, max_events=4, timeout=1.0)

        sub_task = asyncio.create_task(subscriber())
        await asyncio.sleep(0.01)

        await self.adapter.start("demo_recon_15s", speed=0.0)
        await self.adapter.step()
        await self.adapter.step()

        frames = await asyncio.wait_for(sub_task, timeout=2.0)
        events = [f.get("event") for f in frames]

        self.assertIn("demo_status", events)
        self.assertIn("state", events)

        state_frames = [f for f in frames if f.get("event") == "state"]
        self.assertGreaterEqual(len(state_frames), 2)
        self.assertEqual(state_frames[0]["id"], "0")
        self.assertEqual(state_frames[0]["data"]["step_index"], 0)
        self.assertEqual(state_frames[1]["id"], "1")
        self.assertEqual(state_frames[1]["data"]["step_index"], 1)

    async def test_3_reconnection_and_last_event_id_replay(self) -> None:
        # Pre-populate history with 4 steps (0, 1, 2, 3)
        await self.adapter.start("demo_recon_15s", speed=0.0)
        for _ in range(4):
            await self.adapter.step()

        # Connect with last_event_id="1" -> should replay 2 and 3
        frames = await simulate_sse_stream(self.adapter, last_event_id="1", max_events=3, timeout=0.1)
        state_frames = [f for f in frames if f.get("event") == "state"]

        replayed_ids = [f.get("id") for f in state_frames]
        self.assertIn("2", replayed_ids)
        self.assertIn("3", replayed_ids)
        self.assertNotIn("0", replayed_ids)
        self.assertNotIn("1", replayed_ids)

    async def test_4_complete_event_when_scenario_finishes(self) -> None:
        async def subscriber():
            return await simulate_sse_stream(self.adapter, max_events=20, timeout=1.0)

        sub_task = asyncio.create_task(subscriber())
        await asyncio.sleep(0.01)

        await self.adapter.start("demo_dos", speed=0.0)
        for _ in range(10):
            await self.adapter.step()

        frames = await asyncio.wait_for(sub_task, timeout=2.0)
        complete_frames = [f for f in frames if f.get("event") == "complete"]
        self.assertEqual(len(complete_frames), 1)
        self.assertEqual(complete_frames[0]["data"]["scenario"], "demo_dos")
        self.assertEqual(complete_frames[0]["data"]["total_steps"], 10)

    async def test_5_reset_emits_idle_status(self) -> None:
        async def subscriber():
            return await simulate_sse_stream(self.adapter, max_events=5, timeout=1.0)

        sub_task = asyncio.create_task(subscriber())
        await asyncio.sleep(0.01)

        await self.adapter.start("demo_recon_15s", speed=0.0)
        await self.adapter.step()
        await self.adapter.reset()

        frames = await asyncio.wait_for(sub_task, timeout=2.0)
        idle_frames = [
            f for f in frames
            if f.get("event") == "demo_status" and isinstance(f.get("data"), dict) and f["data"].get("status") == "IDLE"
        ]
        self.assertGreater(len(idle_frames), 0)

    async def test_6_multiple_concurrent_subscribers(self) -> None:
        async def subscriber():
            return await simulate_sse_stream(self.adapter, max_events=3, timeout=1.0)

        sub1 = asyncio.create_task(subscriber())
        sub2 = asyncio.create_task(subscriber())
        await asyncio.sleep(0.01)

        await self.adapter.start("demo_recon_15s", speed=0.0)
        await self.adapter.step()

        f1, f2 = await asyncio.gather(
            asyncio.wait_for(sub1, timeout=2.0),
            asyncio.wait_for(sub2, timeout=2.0),
        )

        s1 = [f for f in f1 if f.get("event") == "state"]
        s2 = [f for f in f2 if f.get("event") == "state"]
        self.assertEqual(len(s1), 1)
        self.assertEqual(len(s2), 1)
        self.assertEqual(s1[0]["id"], "0")
        self.assertEqual(s2[0]["id"], "0")

    async def test_7_end_to_end_streaming_pipeline(self) -> None:
        """E2E test: start scenario, stream 8 steps, verify real computed intelligence in SSE payload."""
        async def subscriber():
            return await simulate_sse_stream(self.adapter, max_events=20, timeout=1.0)

        sub_task = asyncio.create_task(subscriber())
        await asyncio.sleep(0.01)

        await self.adapter.start("demo_recon_15s", speed=0.0)
        for _ in range(8):
            await self.adapter.step()

        frames = await asyncio.wait_for(sub_task, timeout=3.0)
        state_frames = [f for f in frames if f.get("event") == "state"]
        self.assertGreaterEqual(len(state_frames), 8)

        # Inspect step 7 (T07 - peak reconnaissance)
        evt7_frame = next(f for f in state_frames if f.get("id") == "7")
        evt7 = evt7_frame["data"]
        self.assertEqual(evt7["step_index"], 7)
        self.assertEqual(evt7["logical_time_str"], "T07 (070s)")
        self.assertEqual(evt7["primary_stage"], "Reconnaissance")
        self.assertGreater(len(evt7["forecast_feature_contributions"]), 0)
        self.assertEqual(evt7["security_explanation"]["primary_stage"], "Reconnaissance")
        self.assertIn("dst_port_diversity", evt7["current_state_summary"])
        self.assertGreater(evt7["current_risk_score"], 0.1)


if __name__ == "__main__":
    unittest.main()
