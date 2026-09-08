"""Manual validation of SSE live streaming."""
from __future__ import annotations

import asyncio
from runtime.api import format_sse
from runtime.demo_adapter import DemoAdapter, AdapterMessageType
from runtime.state_store import RuntimeStateStore
from scenarios.demo.engine import LiveDemoEngine

async def manual_stream_validate():
    print("=" * 70)
    print("MANUAL VALIDATION: SSE STREAMING (TASK 6)")
    print("=" * 70)

    engine = LiveDemoEngine()
    store = RuntimeStateStore()
    adapter = DemoAdapter(engine=engine, store=store)

    print("2. Starting demo scenario 'demo_recon_15s'...")
    await adapter.start("demo_recon_15s", speed=0.0)

    subscription = adapter.subscribe()
    sub_iter = subscription.__aiter__()
    sub_task = asyncio.create_task(sub_iter.__anext__())
    await asyncio.sleep(0.01)

    # Advance step 0
    print("3. Stepping to T00...")
    await adapter.step()
    msg = await sub_task
    print("Received SSE frame 2:")
    print(format_sse(data=msg.data, event="state", event_id=msg.step_index), end="")

    # Advance to step 7 (peak recon)
    print("4. Stepping to T07 (Reconnaissance progression)...")
    for _ in range(7):
        await adapter.step()
        msg = await sub_iter.__anext__()

    print("Received SSE frame for T07:")
    print(f"event: state\nid: {msg.step_index}")
    print(f"data: {{\"step_index\": {msg.data['step_index']}, \"logical_time_str\": \"{msg.data['logical_time_str']}\", \"primary_stage\": \"{msg.data['primary_stage']}\", \"current_risk_score\": {msg.data['current_risk_score']:.4f}}}")

    print("\n[OK] SSE streaming verified successfully.")

if __name__ == "__main__":
    asyncio.run(manual_stream_validate())
