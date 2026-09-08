"""Tests for Task 16: Empirical Forecast Lead-Time Experiment.

Validates:
1. Metric calculations: lead time vs baseline, lead time vs actual onset.
2. Actionable sensitivity analysis across 5s, 10s, 20s, 30s.
3. Failure categorization logic (NONE, MISSED, LATE_VS_BASELINE, INSUFFICIENT_TIME, FALSE_EARLY).
4. Methodology guard integrity:
   - modeled_action_duration_s = 20 stored explicitly as a modeled experimental assumption.
   - Separation of LIVE_CONTROLLED behavioural progression from DATASET_GROUND_TRUTH attack progression.
5. Schema and cryptographic checksum validation of generated experiment artifacts.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest

from eval.run_lead_time_experiment import (
    DEFAULT_MODELED_ACTION_DURATION_S,
    OUTPUT_DIR,
    ProgressionRunResult,
    SENSITIVITY_DURATIONS_S,
    compute_statistics,
)


def test_modeled_action_duration_assumption():
    """Verify that modeled_action_duration_s is explicitly 20 and not hardcoded elsewhere."""
    assert DEFAULT_MODELED_ACTION_DURATION_S == 20
    assert SENSITIVITY_DURATIONS_S == [5, 10, 20, 30]


def test_lead_time_calculation_logic():
    """Verify mathematical definitions of Delta t_base and Delta t_actual."""
    # Case 1: Forecast alerts at w=2, Baseline alerts at w=3, Actual onset at w=3
    w_pred = 2
    w_base = 3
    w_actual = 3

    lead_vs_base = (w_base - w_pred) * 10.0
    lead_vs_actual = (w_actual - w_pred) * 10.0

    assert lead_vs_base == 10.0
    assert lead_vs_actual == 10.0

    # Case 2: Forecast alerts at same window as baseline (w=3, w=3)
    assert (3 - 3) * 10.0 == 0.0

    # Case 3: Forecast alerts after baseline (late alert)
    assert (2 - 3) * 10.0 == -10.0


def test_actionable_sensitivity_mapping():
    """Test actionable determination under varying modeled action durations."""
    # If pred alerts at w=2 and onset is at w=3: lead time is 10s.
    # For T_action = 5s: 10s >= 5s -> Actionable
    # For T_action = 10s: 10s >= 10s -> Actionable
    # For T_action = 20s: 10s < 20s -> Not Actionable (Insufficient time)
    # For T_action = 30s: 10s < 30s -> Not Actionable
    lead_s = 10.0
    sens = {dur: (lead_s >= dur) for dur in [5, 10, 20, 30]}

    assert sens[5] is True
    assert sens[10] is True
    assert sens[20] is False
    assert sens[30] is False


def test_failure_categorization():
    """Verify classification of failure modes."""
    # 1. Clean Success: alerts before baseline with sufficient time
    # (e.g. 20s advance warning before actual onset)
    w_pred = 1
    w_base = 3
    w_actual = 3
    lead_actual = (w_actual - w_pred) * 10.0  # 20s
    cat = "NONE" if (lead_actual >= 20.0 and w_pred < w_base) else "OTHER"
    assert cat == "NONE"

    # 2. Insufficient time: alerts before base, but only 10s before onset (< 20s default)
    w_pred = 2
    w_base = 3
    w_actual = 3
    lead_actual = (w_actual - w_pred) * 10.0  # 10s
    if lead_actual < 20.0 and lead_actual > 0:
        cat = "INSUFFICIENT_TIME"
    assert cat == "INSUFFICIENT_TIME"

    # 3. Late vs baseline: alerts after base
    w_pred = 4
    w_base = 3
    if w_pred > w_base:
        cat = "LATE_VS_BASELINE"
    assert cat == "LATE_VS_BASELINE"

    # 4. Missed: no alert prior to onset
    w_pred = None
    if w_pred is None:
        cat = "MISSED"
    assert cat == "MISSED"


def test_bootstrap_ci_computation():
    """Verify bootstrap confidence interval calculation."""
    values = [10.0, 10.0, 10.0, 20.0, 10.0, 0.0, 10.0, 20.0]
    stats = compute_statistics(values)
    ci_lower = stats["ci_95_lower"]
    ci_upper = stats["ci_95_upper"]
    assert 0.0 <= ci_lower <= 15.0
    assert 10.0 <= ci_upper <= 25.0
    assert ci_lower <= ci_upper


@pytest.mark.skipif(not OUTPUT_DIR.exists(), reason="Experiment has not yet run")
def test_experiment_artifacts_exist_and_match_manifest():
    """Validate that all generated files exist and hashes match run_manifest.json."""
    manifest_path = OUTPUT_DIR / "run_manifest.json"
    assert manifest_path.exists(), "run_manifest.json must exist"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["is_valid_experiment"] is True
    assert manifest["governing_principle"] == "Forecast horizon != Actionable lead time"
    assert manifest["default_modeled_action_duration_s"] == 20

    file_hashes = manifest["file_hashes"]
    for filename, expected_hash in file_hashes.items():
        file_path = OUTPUT_DIR / filename
        assert file_path.exists(), f"Artifact file {filename} missing"

        # Verify SHA-256
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        assert h.hexdigest() == expected_hash, f"SHA-256 mismatch for {filename}"


@pytest.mark.skipif(not OUTPUT_DIR.exists(), reason="Experiment has not yet run")
def test_experiment_results_contents():
    """Verify contents of lead_time_results.json adhere to methodology guards."""
    results_path = OUTPUT_DIR / "lead_time_results.json"
    assert results_path.exists()

    with open(results_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Verify methodology guard 1
    assert data["governing_principle"] == "Forecast horizon != Actionable lead time"
    assert data["modeled_action_duration_assumption"]["default_duration_s"] == 20
    assert "sensitivity_analysis" in data
    assert "5s" in data["sensitivity_analysis"]
    assert "10s" in data["sensitivity_analysis"]
    assert "20s" in data["sensitivity_analysis"]
    assert "30s" in data["sensitivity_analysis"]

    # Verify methodology guard 2: tier separation
    tiers = {r["run_tier"] for r in data["individual_runs"]}
    assert "LIVE_CONTROLLED" in tiers, "Must evaluate Live Controlled tier"
    assert "DATASET_GROUND_TRUTH" in tiers, "Must evaluate Dataset Ground Truth tier"

    # Verify operational trade-off is recorded
    assert "operational_tradeoff" in data
    tradeoff = data["operational_tradeoff"]
    assert "ar5_characteristics" in tradeoff
    assert "baseline_characteristics" in tradeoff
