"""Runtime DemoAdapter wrapping the live intelligence pipeline (SIH 26153)."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, Generator, Sequence

from core.topology.builder import build_minimal_demo_topology
from runtime.state_store import DemoStatus, RuntimeSnapshot, RuntimeStateStore
from scenarios.demo.engine import DemoEvent, LiveDemoEngine
from scenarios.demo.scenarios import get_demo_scenario_states


class AdapterMessageType(str, Enum):
    EVENT = "event"
    STATUS = "status"
    COMPLETED = "completed"
    ERROR = "error"
    RECONSIDERATION = "reconsideration"


@dataclass(frozen=True)
class DemoAdapterMessage:
    """Standard message broadcast to subscribers."""
    message_type: AdapterMessageType
    data: dict[str, Any]
    step_index: int | None = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_type": self.message_type.value,
            "step_index": self.step_index,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }


class DemoAdapter:
    """
    Runtime state machine and timer controller wrapping the existing LiveDemoEngine.

    Delegates canonical state, session metadata, and event history to RuntimeStateStore.
    Coordinates playback across scenarios without reimplementing or duplicating
    any forecasting, security bridge, risk, priority, or decision logic.
    """

    def __init__(
        self,
        engine: LiveDemoEngine | None = None,
        base_step_delay: float = 4.0,
        store: RuntimeStateStore | None = None,
    ) -> None:
        if engine is not None:
            self.engine = engine
        else:
            demo_topology = build_minimal_demo_topology()
            # Auto-load authoritative AR(5) model if present
            model_dir = Path("artifacts/models/ar5_authoritative")
            if model_dir.exists() and (model_dir / "metadata.json").exists():
                try:
                    from runtime.train_authoritative_model import load_ar_model
                    ar_model, scales = load_ar_model(model_dir)
                    self.engine = LiveDemoEngine(ar_model=ar_model, scales=scales, topology=demo_topology)
                except Exception:
                    self.engine = LiveDemoEngine(topology=demo_topology)
            else:
                self.engine = LiveDemoEngine(topology=demo_topology)

        self.base_step_delay = max(0.001, float(base_step_delay))
        self.speed: float = 1.0

        # Canonical single source of truth for runtime state and history
        self.store = store if store is not None else RuntimeStateStore()

        # Generator & Concurrency internals
        self._generator: Generator[DemoEvent, None, None] | None = None
        self._timer_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()
        self._subscribers: set[asyncio.Queue[DemoAdapterMessage]] = set()

    # Delegated state properties to RuntimeStateStore
    @property
    def status(self) -> DemoStatus:
        return self.store.status

    @property
    def scenario(self) -> str | None:
        return self.store.scenario

    @property
    def session_id(self) -> str | None:
        return self.store.session_id

    @property
    def current_step(self) -> int:
        return self.store.current_step

    @property
    def total_steps(self) -> int:
        return self.store.total_steps

    @property
    def current_event(self) -> DemoEvent | None:
        return self.store.current_event

    @property
    def event_history(self) -> list[DemoEvent]:
        return self.store.get_event_history()

    def get_status(self) -> dict[str, Any]:
        """Return the current adapter status summary."""
        info = self.store.get_session_info()
        info["speed"] = self.speed
        return info

    def get_snapshot(self) -> RuntimeSnapshot:
        """Return a full snapshot from the canonical store."""
        return self.store.get_snapshot()

    def _broadcast(self, message: DemoAdapterMessage) -> None:
        """Broadcast a message to all active subscriber queues (thread-safe)."""
        for q in list(self._subscribers):
            try:
                # Check if current running loop matches queue's loop
                try:
                    current_loop = asyncio.get_running_loop()
                except RuntimeError:
                    current_loop = None

                q_loop = getattr(q, "_loop", None)
                if q_loop is not None and q_loop.is_running() and q_loop != current_loop:
                    q_loop.call_soon_threadsafe(q.put_nowait, message)
                else:
                    q.put_nowait(message)
            except Exception:
                try:
                    q.put_nowait(message)
                except Exception:
                    pass

    def _broadcast_error(self, error_message: str) -> None:
        """Broadcast an error message."""
        msg = DemoAdapterMessage(
            message_type=AdapterMessageType.ERROR,
            data={"error": error_message, "status": self.status.value},
            step_index=self.current_step if self.current_step >= 0 else None,
        )
        self._broadcast(msg)

    def _stop_timer_task(self) -> None:
        """Safely cancel the background timer task if running."""
        if self._timer_task is not None and not self._timer_task.done():
            self._timer_task.cancel()
        self._timer_task = None

    def _start_timer_task(self) -> None:
        """Safely start the background timer task."""
        self._stop_timer_task()
        if self.speed > 0:
            self._timer_task = asyncio.create_task(self._timer_loop())

    async def _timer_loop(self) -> None:
        """Internal asynchronous timer loop for automated stepping."""
        try:
            while self.status == DemoStatus.RUNNING:
                event = await self.step()
                if event is None or self.status != DemoStatus.RUNNING:
                    break
                delay = max(0.001, self.base_step_delay / self.speed)
                await asyncio.sleep(delay)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._broadcast_error(str(e))

    async def start(
        self,
        scenario: str = "demo_golden_attack",
        speed: float = 1.0,
    ) -> dict[str, Any]:
        """
        Start or restart execution for the specified scenario.
        """
        # Validate scenario first
        try:
            states = get_demo_scenario_states(scenario)
        except Exception as e:
            self._broadcast_error(f"Failed to load scenario '{scenario}': {e}")
            raise ValueError(f"Unknown or invalid scenario: '{scenario}'") from e

        async with self._lock:
            # Stop any existing timer
            self._stop_timer_task()

            self.speed = max(0.0, float(speed))

            # Initialize session in canonical store
            self.store.create_session(scenario=scenario, total_steps=len(states))

            # Create generator from the existing LiveDemoEngine
            self._generator = self.engine.stream_scenario(states)

            # Broadcast status change
            status_msg = DemoAdapterMessage(
                message_type=AdapterMessageType.STATUS,
                data=self.get_status(),
                step_index=-1,
            )
            self._broadcast(status_msg)

        # Start timer task outside lock if speed > 0
        if self.speed > 0:
            self._start_timer_task()

        return self.get_status()

    async def pause(self) -> dict[str, Any]:
        """
        Pause running playback and preserve position.
        """
        async with self._lock:
            if self.status == DemoStatus.PAUSED:
                return self.get_status()

            if self.status in (DemoStatus.IDLE, DemoStatus.COMPLETED):
                raise RuntimeError(f"Cannot pause when in {self.status.value} state")

            self._stop_timer_task()
            self.store.set_status(DemoStatus.PAUSED)

            status_msg = DemoAdapterMessage(
                message_type=AdapterMessageType.STATUS,
                data=self.get_status(),
                step_index=self.current_step if self.current_step >= 0 else None,
            )
            self._broadcast(status_msg)

        return self.get_status()

    async def resume(self) -> dict[str, Any]:
        """
        Resume playback from paused state.
        """
        async with self._lock:
            if self.status == DemoStatus.RUNNING:
                return self.get_status()

            if self.status != DemoStatus.PAUSED:
                raise RuntimeError(f"Cannot resume from {self.status.value} state. Call start() first.")

            self.store.set_status(DemoStatus.RUNNING)

            status_msg = DemoAdapterMessage(
                message_type=AdapterMessageType.STATUS,
                data=self.get_status(),
                step_index=self.current_step if self.current_step >= 0 else None,
            )
            self._broadcast(status_msg)

        if self.speed > 0:
            self._start_timer_task()

        return self.get_status()

    async def step(self) -> DemoEvent | None:
        """
        Advance exactly one step through the LiveDemoEngine generator.
        """
        async with self._lock:
            if self.status == DemoStatus.IDLE:
                raise RuntimeError("Cannot step when demo is IDLE. Call start() first.")

            if self.status == DemoStatus.COMPLETED or self._generator is None:
                return None

            try:
                event = next(self._generator)
                # Store takes ownership of event history and step updates
                self.store.append_event(event)

                # Broadcast step event
                evt_msg = DemoAdapterMessage(
                    message_type=AdapterMessageType.EVENT,
                    data=event.to_dict(),
                    step_index=event.step_index,
                )
                self._broadcast(evt_msg)

                # If this was the final step of the scenario
                if self.current_step >= self.total_steps - 1:
                    self.store.set_status(DemoStatus.COMPLETED)
                    self._stop_timer_task()
                    comp_msg = DemoAdapterMessage(
                        message_type=AdapterMessageType.COMPLETED,
                        data={
                            "scenario": self.scenario,
                            "total_steps": self.total_steps,
                            "final_step": self.current_step,
                        },
                        step_index=self.current_step,
                    )
                    self._broadcast(comp_msg)

                return event

            except StopIteration:
                self.store.set_status(DemoStatus.COMPLETED)
                self._stop_timer_task()
                comp_msg = DemoAdapterMessage(
                    message_type=AdapterMessageType.COMPLETED,
                    data={
                        "scenario": self.scenario,
                        "total_steps": self.total_steps,
                        "final_step": self.current_step,
                    },
                    step_index=self.current_step,
                )
                self._broadcast(comp_msg)
                return None

    async def reset(self) -> dict[str, Any]:
        """
        Stop execution, clear current state and history in store, and return to IDLE.
        """
        async with self._lock:
            self._stop_timer_task()
            self._generator = None
            self.store.reset()

            status_msg = DemoAdapterMessage(
                message_type=AdapterMessageType.STATUS,
                data=self.get_status(),
                step_index=None,
            )
            self._broadcast(status_msg)

        return self.get_status()

    async def set_speed(self, speed: float) -> dict[str, Any]:
        """
        Adjust execution speed dynamically.
        """
        async with self._lock:
            new_speed = max(0.0, float(speed))
            self.speed = new_speed

            if self.status == DemoStatus.RUNNING:
                if self.speed > 0:
                    self._start_timer_task()
                else:
                    self._stop_timer_task()

            status_msg = DemoAdapterMessage(
                message_type=AdapterMessageType.STATUS,
                data=self.get_status(),
                step_index=self.current_step if self.current_step >= 0 else None,
            )
            self._broadcast(status_msg)

        return self.get_status()

    async def subscribe(self) -> AsyncGenerator[DemoAdapterMessage, None]:
        """
        Asynchronous generator subscribing to adapter events, status changes,
        errors, and completion notifications.
        """
        queue: asyncio.Queue[DemoAdapterMessage] = asyncio.Queue()
        self._subscribers.add(queue)
        try:
            while True:
                msg = await queue.get()
                yield msg
        finally:
            self._subscribers.discard(queue)
