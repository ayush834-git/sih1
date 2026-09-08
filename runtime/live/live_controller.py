"""Live Packet Capture Controller integrating capture, generator, state builder, and forecasting (SIH 26153)."""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, List, Sequence

from core.contracts import NetworkState, new_id
from runtime.demo_adapter import AdapterMessageType, DemoAdapter, DemoAdapterMessage
from runtime.live.flow_accumulator import FlowAccumulator, FlowRecord
from runtime.live.packet_capture import LivePacketCapture
from runtime.live.packet_parser import ParsedPacket
from runtime.live.provenance import create_experiment_artifacts, EXPERIMENT_DIR
from runtime.live.state_builder import build_network_state_from_packets
from runtime.live.traffic_generator import ControlledTrafficGenerator
from runtime.state_store import DemoStatus, RuntimeStateStore
from scenarios.demo.engine import DemoEvent, LiveDemoEngine

logger = logging.getLogger("live_controller")


class LiveCaptureController:
    """Coordinates real Windows packet capture, controlled traffic generation,
    causal 10-second state construction, and live forecasting through the existing engine.
    """

    def __init__(
        self,
        adapter: DemoAdapter,
        window_duration_s: float = 10.0,
    ) -> None:
        self.adapter = adapter
        self.store = adapter.store
        self.engine = adapter.engine
        self.window_duration_s = float(window_duration_s)

        self.capture: LivePacketCapture | None = None
        self.generator: ControlledTrafficGenerator | None = None
        self._task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

        # Session metrics
        self.run_id: str | None = None
        self.is_active: bool = False
        self.states: List[NetworkState] = []
        self.events: List[DemoEvent] = []
        self.all_captured_packets: List[ParsedPacket] = []
        self.all_flows: List[FlowRecord] = []

    def get_status(self) -> dict[str, Any]:
        """Return live capture controller status summary."""
        cap_stats = self.capture.stats if self.capture else None
        gen_stats = self.generator.stats if self.generator else None

        return {
            "run_id": self.run_id,
            "is_active": self.is_active,
            "execution_mode": "LIVE_PACKET_CAPTURE",
            "packets_captured": cap_stats.packets_captured if cap_stats else 0,
            "in_scope_packets": cap_stats.in_scope_packets if cap_stats else 0,
            "out_of_scope_packets": cap_stats.out_of_scope_packets if cap_stats else 0,
            "isolation_violations": cap_stats.isolation_violations if cap_stats else [],
            "isolation_passed": (cap_stats.out_of_scope_packets == 0 and len(cap_stats.isolation_violations) == 0) if cap_stats else True,
            "states_built": len(self.states),
            "events_emitted": len(self.events),
            "generator_running": gen_stats.is_running if gen_stats else False,
            "generator_scenario": gen_stats.scenario if gen_stats else "none",
        }

    async def start(
        self,
        scenario: str = "baseline",
        duration_windows: int = 2,
        speed: float = 1.0,
        allowed_ports: Sequence[int] = (8765, 8766, 8767, 8768, 8769, 8770),
    ) -> dict[str, Any]:
        """Start a live capture experiment run."""
        async with self._lock:
            if self.is_active:
                raise RuntimeError("Live packet capture is already running.")

            # Mutual exclusion: check if demo replay is active
            if self.adapter.status == DemoStatus.RUNNING and self.store.execution_mode != "LIVE_PACKET_CAPTURE":
                raise RuntimeError("Cannot start live packet capture while Demo Replay is RUNNING.")

            # Generate unique run ID
            self.run_id = f"live-run-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
            self.states.clear()
            self.events.clear()
            self.all_captured_packets.clear()
            self.all_flows.clear()

            # Initialize capture and generator
            self.capture = LivePacketCapture(allowed_ports=allowed_ports)
            self.generator = ControlledTrafficGenerator(ports=list(allowed_ports))

            # Initialize session in RuntimeStateStore with explicit execution_mode
            self.store.create_session(
                scenario=f"live_pcap_{scenario}",
                total_steps=duration_windows,
                session_id=self.run_id,
                execution_mode="LIVE_PACKET_CAPTURE",
            )

            # Start Npcap/TShark capture process
            self.capture.start()

            # Start controlled traffic generator
            self.generator.start(scenario=scenario, speed=speed)
            self.is_active = True

            # Broadcast status change to SSE subscribers
            status_msg = DemoAdapterMessage(
                message_type=AdapterMessageType.STATUS,
                data={
                    **self.adapter.get_status(),
                    "execution_mode": "LIVE_PACKET_CAPTURE",
                    "live_status": self.get_status(),
                },
                step_index=-1,
            )
            self.adapter._broadcast(status_msg)

            # Launch background streaming loop
            self._task = asyncio.create_task(
                self._run_live_loop(duration_windows=duration_windows, speed=speed)
            )

            return self.get_status()

    async def _run_live_loop(self, duration_windows: int, speed: float) -> None:
        """Asynchronous execution loop for 10-second causal state construction and forecasting."""
        logger.info("Starting live capture loop for %d windows", duration_windows)
        
        # Scaling factor: if speed > 1.0, wait window_duration_s / speed in wall clock time,
        # but the logical window duration in the state remains 10.0 seconds.
        wall_wait = max(0.5, self.window_duration_s / max(0.1, speed))
        flow_acc = FlowAccumulator()

        try:
            for step_idx in range(duration_windows):
                if not self.is_active:
                    break

                t_start = time.time()
                await asyncio.sleep(wall_wait)
                t_end = time.time()

                # 1. Retrieve packets strictly in this causal window [t_start, t_end)
                if self.capture is None:
                    break
                window_packets = self.capture.get_packets_in_range(t_start, t_end)
                self.all_captured_packets.extend(window_packets)

                for p in window_packets:
                    flow_acc.add_packet(p)

                # 2. Build schema-compliant NetworkState
                dt_start = datetime.fromtimestamp(t_start, tz=timezone.utc)
                dt_end = dt_start + timedelta(seconds=self.window_duration_s)

                state = build_network_state_from_packets(
                    packets=window_packets,
                    start_time=dt_start,
                    end_time=dt_end,
                    window_index=step_idx,
                    session_id=self.run_id or "live-session",
                    window_duration_s=self.window_duration_s,
                )
                self.states.append(state)

                # 3. Feed NetworkState sequence into the existing LiveDemoEngine
                events_seq = list(self.engine.stream_scenario(self.states))
                event = events_seq[-1]
                self.events.append(event)

                # 4. Record DemoEvent in canonical RuntimeStateStore
                self.store.append_event(event)

                # 5. Broadcast to SSE subscribers with LIVE_PACKET_CAPTURE mode
                event_msg = DemoAdapterMessage(
                    message_type=AdapterMessageType.EVENT,
                    data=event.to_dict(),
                    step_index=step_idx,
                )
                self.adapter._broadcast(event_msg)

            # Mark session completed
            await self.stop()

        except asyncio.CancelledError:
            await self.stop()
        except Exception as e:
            logger.exception("Error in live capture loop: %s", e)
            self.adapter._broadcast_error(f"Live capture error: {e}")
            await self.stop()

    async def stop(self) -> dict[str, Any]:
        """Stop live capture, traffic generation, and generate full audit package."""
        if not self.is_active and self.capture is None:
            return self.get_status()

        self.is_active = False

        current = asyncio.current_task()
        if self._task and not self._task.done() and self._task != current:
            self._task.cancel()
            self._task = None

        gen_stats = self.generator.stop() if self.generator else None
        cap_stats = self.capture.stop() if self.capture else None

        # Collect all flows
        acc = FlowAccumulator()
        for p in self.all_captured_packets:
            acc.add_packet(p)
        self.all_flows = list(acc.get_flows())

        # Update store status
        self.store.set_status(DemoStatus.COMPLETED)

        # Persist full audit artifacts
        if self.run_id and cap_stats and gen_stats:
            create_experiment_artifacts(
                run_id=self.run_id,
                capture_stats=cap_stats,
                generator_stats=gen_stats,
                packets=self.all_captured_packets,
                flows=self.all_flows,
                states=self.states,
                events=self.events,
            )

        # Broadcast completed status
        completed_msg = DemoAdapterMessage(
            message_type=AdapterMessageType.COMPLETED,
            data={
                **self.adapter.get_status(),
                "execution_mode": "LIVE_PACKET_CAPTURE",
                "live_status": self.get_status(),
            },
            step_index=self.store.current_step,
        )
        self.adapter._broadcast(completed_msg)

        return self.get_status()
