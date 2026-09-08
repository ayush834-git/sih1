import unittest
from dataclasses import replace
from core.config import load_settings
from core.contracts import *
from scenarios.smoke_pipeline import run

class DayOneTests(unittest.TestCase):
    def setUp(self): self.result = run(); self.state = self.result["state"]
    def test_config_loads(self):
        settings = load_settings(); self.assertEqual((settings.window_size_seconds, settings.history_depth, settings.trajectory_count, settings.forecast_horizon), (10, 3, 3, 1)); self.assertEqual(settings.scaler, "RobustScaler")
    def test_all_contracts_instantiate(self):
        for name in ("state", "forecast", "trajectory", "trust", "security", "priority", "response"): self.assertIsNotNone(self.result[name])
        self.assertEqual(len(self.result["notifications"]), 4)
    def test_state_rejects_invalid_values(self):
        with self.assertRaises(ValueError): replace(self.state, flow_count=-1)
        with self.assertRaises(ValueError): replace(self.state, is_empty=True)
    def test_no_attack_label_or_infiltration_feature(self):
        self.assertNotIn("infiltration_fraction", self.state.__dataclass_fields__)
        self.assertFalse(any("label" in f or "attack" in f for f in self.state.__dataclass_fields__))
    def test_gap_blocks_transition_capability(self): self.assertFalse(replace(self.state, gap_before=True).transitions_allowed)
    def test_forecast_invariant(self): self.result["forecast"].validate_against(self.state)
    def test_unknown_is_representable_without_benign_fallback(self):
        assessment = self.result["security"]; self.assertTrue(assessment.is_novel); self.assertEqual(assessment.primary_stage.stage_name, "Unknown")
    def test_response_is_non_destructive_and_human_gated(self):
        response = self.result["response"]; self.assertTrue(response.is_reversible); self.assertTrue(response.requires_human)
        with self.assertRaises(ValueError): ResponseRecommendation("x", "p", TrustLevel.LOW, Strategy.MONITOR, [RecommendedAction(ActionType.NO_ACTION, "x", True, ActionUrgency.SOON)], True, False, "invalid")
    def test_role_notifications_follow_schema(self):
        for item in self.result["notifications"]: self.assertTrue(item.should_notify); self.assertNotEqual(item.urgency, NotificationUrgency.NONE); self.assertIn(item.role.value, item.detail)
    def test_offline_smoke_pipeline(self): self.assertEqual(self.result["forecast"].model_id, "DAY1_PLACEHOLDER")

if __name__ == "__main__": unittest.main()
