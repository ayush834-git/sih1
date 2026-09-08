"""Response Adapters for Reversible Execution (SIH 26153 Task 21).

Provides:
- Abstract ResponseAdapter interface
- Pure in-memory DemoResponseAdapter for safe, non-destructive simulation

CRITICAL SAFETY INVARIANT:
No real host, OS, network, or firewall modifications are made.
All operations are fully deterministic, bounded, and reversible.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping, Sequence

from core.authority.models import ActionClass
from core.response_execution.models import ReversibleActionType, ResponseAction


class ResponseAdapter(ABC):
    """
    Abstract adapter boundary for executing reversible response actions.
    """

    @abstractmethod
    def validate(self, action: ResponseAction) -> tuple[bool, str]:
        """Validate if the action is supported and parameters are valid."""
        raise NotImplementedError

    @abstractmethod
    def execute(self, action: ResponseAction) -> tuple[bool, Mapping[str, Any], str]:
        """
        Execute a reversible defensive action.
        Returns: (success: bool, applied_parameters: dict, message: str)
        """
        raise NotImplementedError

    @abstractmethod
    def rollback(self, action: ResponseAction) -> tuple[bool, Mapping[str, Any], str]:
        """
        Rollback an executed action using its defined compensating operation.
        Returns: (success: bool, applied_parameters: dict, message: str)
        """
        raise NotImplementedError

    @abstractmethod
    def get_active_actions(self) -> Sequence[ResponseAction]:
        """Return all currently active reversible actions."""
        raise NotImplementedError

    @abstractmethod
    def get_state(self) -> Mapping[str, Any]:
        """Return current simulated operational state."""
        raise NotImplementedError

    @abstractmethod
    def reset(self) -> None:
        """Reset adapter state (for testing and scenario replay)."""
        raise NotImplementedError


class DemoResponseAdapter(ResponseAdapter):
    """
    Pure in-memory simulation adapter for demonstrations and automated testing.
    Safely models rate-limiting, blocking, endpoint disabling, and posture toggling
    without any real OS or network side effects.
    """

    def __init__(self) -> None:
        self._active_actions: dict[str, ResponseAction] = {}
        self._rate_limits: dict[str, float] = {}       # target_id -> rate_limit_bps
        self._blocked_targets: set[str] = set()         # set of target_ids
        self._disabled_endpoints: set[str] = set()      # set of target_ids
        self._config_toggles: dict[str, bool] = {}     # target_id -> toggle_state
        self._fail_next_execution: bool = False
        self._fail_next_rollback: bool = False

    def set_execution_failure_simulation(self, fail: bool) -> None:
        """Testing hook to simulate adapter execution failures."""
        self._fail_next_execution = fail

    def set_rollback_failure_simulation(self, fail: bool) -> None:
        """Testing hook to simulate adapter rollback failures."""
        self._fail_next_rollback = fail

    def validate(self, action: ResponseAction) -> tuple[bool, str]:
        if not isinstance(action, ResponseAction):
            return False, "Input must be a valid ResponseAction instance"
        if action.action_class == ActionClass.EXECUTE_DESTRUCTIVE_ACTION:
            return False, "EXECUTE_DESTRUCTIVE_ACTION is permanently prohibited"
        if not action.reversibility:
            return False, "Actions executed through DemoResponseAdapter must be reversible"

        params = action.requested_parameters
        if action.action_type == ReversibleActionType.TEMP_RATE_LIMIT:
            rate_limit = params.get("rate_limit_bps", params.get("rate_limit_mbps", 1000.0))
            if not isinstance(rate_limit, (int, float)) or rate_limit <= 0:
                return False, "TEMP_RATE_LIMIT requires a positive numeric rate limit"
        elif action.action_type == ReversibleActionType.DEMO_BLOCK:
            if not action.target_node_id:
                return False, "DEMO_BLOCK requires a non-empty target_node_id"
        elif action.action_type == ReversibleActionType.DEMO_DISABLE_ENDPOINT:
            if not action.target_node_id:
                return False, "DEMO_DISABLE_ENDPOINT requires a non-empty target_node_id"

        return True, "Action validation passed"

    def execute(self, action: ResponseAction) -> tuple[bool, Mapping[str, Any], str]:
        is_valid, reason = self.validate(action)
        if not is_valid:
            return False, {}, f"Validation failed: {reason}"

        if self._fail_next_execution:
            self._fail_next_execution = False
            return False, {}, "Simulated adapter execution failure (e.g. simulated network timeout)"

        target = action.target_node_id
        applied_params = dict(action.requested_parameters)
        applied_params["target_node_id"] = target
        applied_params["action_type"] = action.action_type.value

        if action.action_type == ReversibleActionType.TEMP_RATE_LIMIT:
            rate_limit = applied_params.get("rate_limit_bps", applied_params.get("rate_limit_mbps", 1000.0))
            self._rate_limits[target] = float(rate_limit)
        elif action.action_type == ReversibleActionType.DEMO_BLOCK:
            self._blocked_targets.add(target)
        elif action.action_type == ReversibleActionType.DEMO_DISABLE_ENDPOINT:
            self._disabled_endpoints.add(target)
        elif action.action_type == ReversibleActionType.REVERSIBLE_CONFIG_TOGGLE:
            self._config_toggles[target] = True

        self._active_actions[action.action_id] = action
        return True, applied_params, f"Simulated {action.action_type.value} applied to target '{target}'"

    def rollback(self, action: ResponseAction) -> tuple[bool, Mapping[str, Any], str]:
        if action.action_id not in self._active_actions:
            return False, {}, f"Cannot rollback action '{action.action_id}': not currently active"

        if self._fail_next_rollback:
            self._fail_next_rollback = False
            return False, {}, "Simulated adapter rollback failure"

        target = action.target_node_id
        rollback_params = {
            "target_node_id": target,
            "compensating_action_type": action.compensating_action_type,
            "original_action_id": action.action_id,
        }

        if action.action_type == ReversibleActionType.TEMP_RATE_LIMIT:
            self._rate_limits.pop(target, None)
        elif action.action_type == ReversibleActionType.DEMO_BLOCK:
            self._blocked_targets.discard(target)
        elif action.action_type == ReversibleActionType.DEMO_DISABLE_ENDPOINT:
            self._disabled_endpoints.discard(target)
        elif action.action_type == ReversibleActionType.REVERSIBLE_CONFIG_TOGGLE:
            self._config_toggles.pop(target, None)

        self._active_actions.pop(action.action_id, None)
        return True, rollback_params, f"Compensating action '{action.compensating_action_type}' applied for target '{target}'"

    def get_active_actions(self) -> Sequence[ResponseAction]:
        return list(self._active_actions.values())

    def get_state(self) -> Mapping[str, Any]:
        return {
            "active_rate_limits": dict(self._rate_limits),
            "blocked_targets": sorted(self._blocked_targets),
            "disabled_endpoints": sorted(self._disabled_endpoints),
            "config_toggles": dict(self._config_toggles),
            "active_action_count": len(self._active_actions),
        }

    def reset(self) -> None:
        self._active_actions.clear()
        self._rate_limits.clear()
        self._blocked_targets.clear()
        self._disabled_endpoints.clear()
        self._config_toggles.clear()
        self._fail_next_execution = False
        self._fail_next_rollback = False
