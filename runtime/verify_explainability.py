"""Verify ExplainabilityEngine integration into LiveDemoEngine."""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from runtime.train_authoritative_model import load_ar_model
from scenarios.demo.engine import LiveDemoEngine
from scenarios.demo.scenarios import get_demo_scenario_states


def main() -> None:
    print("=" * 75)
    print("STEP 2 VERIFICATION: ExplainabilityEngine Integration")
    print("=" * 75)

    # Load trained AR(5)
    model_dir = Path("artifacts/models/ar5_authoritative")
    ar_model, scales = load_ar_model(model_dir)
    print(f"[OK] Loaded model: {ar_model.model_name}")

    # Create engine and run demo
    engine = LiveDemoEngine(ar_model=ar_model, scales=scales)
    states = get_demo_scenario_states("demo_recon_15s")
    events = list(engine.stream_scenario(states))
    print(f"[OK] Generated {len(events)} events with explainability")

    # Verify explainability data is present
    errors = []
    for evt in events:
        if not isinstance(evt.forecast_feature_contributions, list):
            errors.append(f"T{evt.step_index}: forecast_feature_contributions is not a list")
        if not isinstance(evt.security_explanation, dict):
            errors.append(f"T{evt.step_index}: security_explanation is not a dict")

    if errors:
        print("[FAIL] Errors found:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    # Check that at least some events have non-empty contributions
    has_contribs = sum(1 for e in events if len(e.forecast_feature_contributions) > 0)
    has_sec_expl = sum(1 for e in events if e.security_explanation.get("primary_stage"))
    print(f"[OK] {has_contribs}/{len(events)} events have forecast feature contributions")
    print(f"[OK] {has_sec_expl}/{len(events)} events have security explanations")

    # Print a sample event's explainability
    sample_idx = 7  # T07 - during reconnaissance
    sample = events[sample_idx]
    print(f"\n--- Sample: T{sample_idx:02d} ({sample.primary_stage}) ---")
    print(f"Stage: {sample.primary_stage} (confidence: {sample.stage_confidence:.2f})")
    print(f"Risk: {sample.current_risk_score:.3f}")

    print("\nForecast Feature Contributions (top 5):")
    for fc in sample.forecast_feature_contributions:
        print(f"  {fc['feature_name']:22s} dir={fc['signed_direction']:8s} "
              f"norm={fc['normalized_contribution']:.4f} delta={fc['predicted_delta']:+.4f} "
              f"evidence={fc['evidence_type']}")

    sec = sample.security_explanation
    print(f"\nSecurity Explanation:")
    print(f"  Primary stage: {sec.get('primary_stage', 'N/A')}")
    print(f"  Confidence: {sec.get('confidence', 0):.4f}")
    print(f"  Trust: {sec.get('trust_level', 'N/A')}")
    print(f"  Supporting evidence ({len(sec.get('supporting_evidence', []))}):")
    for ev in sec.get("supporting_evidence", [])[:3]:
        print(f"    - {ev[:80]}")
    print(f"  Counter evidence ({len(sec.get('counter_evidence', []))}):")
    for ev in sec.get("counter_evidence", [])[:3]:
        print(f"    - {ev[:80]}")
    print(f"  Contributing features ({len(sec.get('top_contributing_features', []))}):")
    for fc in sec.get("top_contributing_features", [])[:3]:
        print(f"    - {fc['feature_name']}: {fc['description'][:70]}")
    print(f"  Limitations ({len(sec.get('limitations', []))}):")
    for lim in sec.get("limitations", []):
        print(f"    - {lim[:80]}")

    # Verify to_dict() round-trip includes explainability
    d = sample.to_dict()
    assert "forecast_feature_contributions" in d, "forecast_feature_contributions missing from to_dict()"
    assert "security_explanation" in d, "security_explanation missing from to_dict()"
    assert len(d["forecast_feature_contributions"]) > 0, "Empty forecast_feature_contributions in to_dict()"
    assert d["security_explanation"].get("primary_stage"), "Empty security_explanation in to_dict()"
    print("\n[OK] to_dict() round-trip includes all explainability fields")

    # Verify serialization to JSON works
    json_str = json.dumps(d, default=str)
    parsed = json.loads(json_str)
    assert len(parsed["forecast_feature_contributions"]) == len(d["forecast_feature_contributions"])
    print("[OK] JSON serialization/deserialization verified")

    # Show the contradiction phase (T09-T10)
    print("\n--- Contradiction Phase Analysis (T09-T10) ---")
    for t in [9, 10]:
        e = events[t]
        sec_e = e.security_explanation
        print(f"\n  T{t:02d}: Stage={e.primary_stage} Conf={e.stage_confidence:.2f} Risk={e.current_risk_score:.3f}")
        if sec_e.get("counter_evidence"):
            print(f"    Counter-evidence:")
            for ce in sec_e["counter_evidence"]:
                print(f"      - {ce[:80]}")
        if sec_e.get("current_vs_forecast_breakdown"):
            print(f"    Current vs Forecast:")
            for feat, desc in sec_e["current_vs_forecast_breakdown"].items():
                print(f"      {feat}: {desc[:70]}")

    print(f"\n{'=' * 75}")
    print("STEP 2 VERIFICATION: ALL CHECKS PASSED")
    print(f"{'=' * 75}")


if __name__ == "__main__":
    main()
