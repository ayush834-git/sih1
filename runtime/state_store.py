"""Canonical In-Memory Runtime State & Event Store (SIH 26153)."""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Sequence

from core.contracts import new_id
from scenarios.demo.engine import DemoEvent


class DemoStatus(str, Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"


@dataclass(frozen=True)
class RuntimeSnapshot:
    """Immutable snapshot of the runtime state at a point in time."""
    session_id: str | None
    scenario: str | None
    status: DemoStatus
    current_step: int
    total_steps: int
    current_event: DemoEvent | None
    history_count: int
    updated_at: datetime
    execution_mode: str = "DEMO"

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "scenario": self.scenario,
            "status": self.status.value,
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "current_event": self.current_event.to_dict() if self.current_event else None,
            "history_count": self.history_count,
            "updated_at": self.updated_at.isoformat(),
            "execution_mode": self.execution_mode,
        }


class RuntimeStateStore:
    """
    Canonical, thread-safe in-memory store for session metadata,
    current pipeline state, and bounded event history.
    """

    def __init__(self, max_history_size: int = 500) -> None:
        if max_history_size < 1:
            raise ValueError(f"max_history_size must be >= 1, got {max_history_size}")

        self._max_history_size = int(max_history_size)
        self._lock = threading.RLock()

        # Session state
        self._session_id: str | None = None
        self._scenario: str | None = None
        self._status: DemoStatus = DemoStatus.IDLE
        self._current_step: int = -1
        self._total_steps: int = 0
        self._current_event: DemoEvent | None = None
        self._history: deque[DemoEvent] = deque(maxlen=self._max_history_size)
        self._updated_at: datetime = datetime.now()
        self._execution_mode: str = "DEMO"

    @property
    def execution_mode(self) -> str:
        with self._lock:
            return self._execution_mode

    @property
    def session_id(self) -> str | None:
        with self._lock:
            return self._session_id

    @property
    def scenario(self) -> str | None:
        with self._lock:
            return self._scenario

    @property
    def status(self) -> DemoStatus:
        with self._lock:
            return self._status

    @property
    def current_step(self) -> int:
        with self._lock:
            return self._current_step

    @property
    def total_steps(self) -> int:
        with self._lock:
            return self._total_steps

    @property
    def current_event(self) -> DemoEvent | None:
        with self._lock:
            return self._current_event

    @property
    def max_history_size(self) -> int:
        return self._max_history_size

    @property
    def updated_at(self) -> datetime:
        with self._lock:
            return self._updated_at

    def create_session(
        self,
        scenario: str,
        total_steps: int,
        session_id: str | None = None,
        execution_mode: str = "DEMO",
    ) -> RuntimeSnapshot:
        """Initialize a new runtime session and transition status to RUNNING."""
        if not scenario:
            raise ValueError("Scenario name cannot be empty")
        if total_steps < 1:
            raise ValueError(f"total_steps must be >= 1, got {total_steps}")

        with self._lock:
            self._session_id = session_id or f"sess-{new_id('s')[:8]}"
            self._scenario = scenario
            self._total_steps = int(total_steps)
            self._current_step = -1
            self._current_event = None
            self._history.clear()
            self._status = DemoStatus.RUNNING
            self._updated_at = datetime.now()
            self._execution_mode = execution_mode
            return self.get_snapshot()

    def set_status(self, status: DemoStatus | str) -> DemoStatus:
        """Update the session status."""
        if isinstance(status, str):
            status = DemoStatus(status)

        with self._lock:
            self._status = status
            self._updated_at = datetime.now()
            return self._status

    def append_event(self, event: DemoEvent) -> None:
        """
        Append a DemoEvent to the store.
        Validates monotonic step sequence and updates current state.
        """
        if not isinstance(event, DemoEvent):
            raise TypeError(f"Expected DemoEvent instance, got {type(event).__name__}")

        with self._lock:
            if self._status == DemoStatus.IDLE or self._session_id is None:
                raise RuntimeError("Cannot append event: no active session in store (status is IDLE)")

            # Validate monotonic step sequence
            expected_step = 0 if self._current_step == -1 else self._current_step + 1
            if event.step_index != expected_step:
                raise ValueError(
                    f"Invalid step_index {event.step_index}; expected monotonic step {expected_step}"
                )

            self._history.append(event)
            self._current_event = event
            self._current_step = event.step_index
            self._updated_at = datetime.now()

            # Automatically transition to COMPLETED if last step is reached
            if self._current_step >= self._total_steps - 1:
                self._status = DemoStatus.COMPLETED

    def get_snapshot(self) -> RuntimeSnapshot:
        """Get an immutable snapshot of current state."""
        with self._lock:
            return RuntimeSnapshot(
                session_id=self._session_id,
                scenario=self._scenario,
                status=self._status,
                current_step=self._current_step,
                total_steps=self._total_steps,
                current_event=self._current_event,
                history_count=len(self._history),
                updated_at=self._updated_at,
                execution_mode=self._execution_mode,
            )

    def get_current_event(self) -> DemoEvent | None:
        """Get the latest DemoEvent."""
        with self._lock:
            return self._current_event

    def get_event_history(
        self,
        limit: int | None = None,
        since_step: int | None = None,
    ) -> list[DemoEvent]:
        """
        Retrieve ordered event history with optional filtering and limit.
        """
        with self._lock:
            events = list(self._history)

            if since_step is not None:
                events = [e for e in events if e.step_index >= since_step]

            if limit is not None:
                if limit < 0:
                    raise ValueError(f"limit must be >= 0, got {limit}")
                events = events[-limit:] if limit > 0 else []

            return events

    def get_event(self, step_index: int) -> DemoEvent | None:
        """Retrieve an event by its step index."""
        with self._lock:
            for event in self._history:
                if event.step_index == step_index:
                    return event
            return None

    def get_session_info(self) -> dict[str, Any]:
        """Return a lightweight session dictionary."""
        with self._lock:
            return {
                "session_id": self._session_id,
                "scenario": self._scenario,
                "status": self._status.value,
                "current_step": self._current_step,
                "total_steps": self._total_steps,
                "history_count": len(self._history),
                "updated_at": self._updated_at.isoformat(),
                "execution_mode": self._execution_mode,
            }

    def reset(self) -> None:
        """Clear all session data and return store to IDLE."""
        with self._lock:
            self._session_id = None
            self._scenario = None
            self._status = DemoStatus.IDLE
            self._current_step = -1
            self._total_steps = 0
            self._current_event = None
            self._history.clear()
            self._updated_at = datetime.now()
            self._execution_mode = "DEMO"

    def clear(self) -> None:
        """Alias for reset()."""
        self.reset()
