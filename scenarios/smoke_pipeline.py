"""Deterministic structural-only Day-1 pipeline; it makes no security claims."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from core.contracts import *
from core.config import load_settings

def _state() -> NetworkState:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return NetworkState("synthetic-0001", start, start + timedelta(seconds=10), 10, 2, 120.0, 4.0, 0.5, 1, 1, 2, 2, 1.0, .5, 1, 1, 1, 0, .25, 0.0, .1, .01, None, 60.0, 2.0, 100.0, None, None, None, None, None, None, Source.CSV, 1.0, False, False, False, "synthetic-session", sha256(b"synthetic-day-1").hexdigest())

def run() -> dict[str, object]:
    settings = load_settings(); state = _state(); now = state.timestamp_end
    delta = {name: 0.0 for name in STATE_FEATURES}; predicted = state.feature_values()
    forecast = Forecast(new_id("forecast"), state.window_id, now, settings.forecast_horizon, delta, predicted, "DAY1_PLACEHOLDER", "0", STATE_SCHEMA_HASH, now, None)
    forecast.validate_against(state)
    trajectory = Trajectory(new_id("trajectory"), state.window_id, [TrajectoryStep(0, forecast)], 0.0, None, True, None, now, now)
    trust = TrustAssessment(new_id("trust"), forecast.forecast_id, 0.0, 0.0, 0.0, 0.0, 0.0, state.data_quality, 0.0, TrustLevel.INSUFFICIENT, [TrustFactor("day_1_placeholder", 0.0, Direction.DECREASES_TRUST)])
    unknown = StageCandidate("Unknown", None, 1.0, True)
    security = SecurityAssessment(new_id("security"), trajectory.trajectory_id, trust.assessment_id, {}, [unknown], unknown, [], True)
    priority = PriorityAssessment(new_id("priority"), security.assessment_id, 0.0, .5, .5, .5, .5, 0.0, .5, PriorityLevel.MEDIUM, "Synthetic Day-1 placeholder; no prediction or security conclusion.")
    response = ResponseRecommendation(new_id("response"), priority.assessment_id, trust.trust_level, Strategy.ESCALATE, [RecommendedAction(ActionType.INCREASE_MONITORING, "synthetic-telemetry", True, ActionUrgency.SOON)], True, True, "Structural smoke-test escalation only.")
    notifications = [RoleNotification(new_id("notice"), response.recommendation_id, role, True, NotificationUrgency.HIGH_PRIORITY, f"Synthetic placeholder for {role.value}", f"Day-1 structural test: {role.value} receives role-specific placeholder content.", ["synthetic-telemetry"], trust.composite_trust, now) for role in Role]
    return {"settings": settings, "state": state, "forecast": forecast, "trajectory": trajectory, "trust": trust, "security": security, "priority": priority, "response": response, "notifications": notifications}

if __name__ == "__main__":
    result = run()
    print(f"Day-1 synthetic smoke pipeline passed ({len(result['notifications'])} role notifications).")
