# First-Class Reconsideration Architecture (Task 17)

## What Reconsideration Is

Reconsideration is a **closed-loop revision mechanism** that evaluates new
telemetry for consistency with its prior forecast and revises downstream
assessments via pipeline re-execution when evidence conflicts.

When a new 10-second `NetworkState` observation arrives, the reconsideration
engine:
1. Compares the prior step's h=1 forecast against the actual observed values
2. Classifies the relationship as CONFIRMING, CONTRADICTORY, MIXED, or INSUFFICIENT
3. If warranted, re-runs the existing pipeline with conflict-adjusted trust
4. Records the prior-vs-revised delta as an auditable `ReconsiderationEvent`

## What Reconsideration Is NOT

- **Not autonomous intelligence.** The system evaluates evidence consistency
  and invokes existing pipeline components. It does not make novel inferences.
- **Not a separate model.** There is no reconsideration-specific ML model.
  The same AR(5), BehavioralSecurityBridge, SecurityRiskEngine, PriorityEngine,
  and ResponseRecommendationEngine are reused.
- **Not a fabricated risk override.** Revised risk/priority/response values
  come entirely from pipeline re-execution with adjusted trust. No values are
  manufactured from conflict type alone.

## Data Flow

```
Prior Forecast (h=1 prediction from step T_{n-1})
    ↓
New Observation (actual NetworkState at step T_n)
    ↓
Conflict Assessment
    → Compare per-feature: |actual_delta - predicted_delta| / scale
    → Classify: CONFIRMING | CONTRADICTORY | MIXED | INSUFFICIENT
    ↓
[If CONTRADICTORY or qualifying MIXED]
Trust Adjustment
    → penalty = min(0.30, mean_scaled_deviation × 0.10)
    → adjusted_trust = max(0.05, prior_trust - penalty)
    → This is the ONLY synthetic input
    ↓
Pipeline Re-execution (same components, adjusted trust)
    → BehavioralSecurityBridge.extract_signatures()
    → BehavioralSecurityBridge.infer_stage_hypotheses()
    → BehavioralSecurityBridge.compute_security_risk_trajectory()
    → PriorityEngine.assess_priority()
    → ResponseRecommendationEngine.generate_recommendation()
    ↓
ReconsiderationEvent
    → Prior assessment snapshot
    → Conflict evidence
    → Revised assessment (from real pipeline output)
    → Revision magnitude, type, reason
    → Provenance hash (SHA-256)
    ↓
DemoEvent carries revised assessment as single current truth
    → Additional RECONSIDERATION SSE message with revision metadata
```

## Conflict Type Decision Table

| ConflictType    | Revision Warranted? | Rationale |
|-----------------|---------------------|-----------|
| CONFIRMING      | No                  | Prior forecast was consistent with observed reality. No revision needed. |
| CONTRADICTORY   | Yes                 | Significant deviation detected across all assessed features. Re-run pipeline with conflict-adjusted trust. |
| MIXED           | Yes (if any feature exceeds threshold) | At least one significant mismatch exists. Pipeline re-execution may or may not produce a different result. |
| INSUFFICIENT    | No                  | Cannot assess conflict (first step, data quality too low, no prior predictions available). |

## Deviation Direction Classification

| Direction           | Meaning |
|---------------------|---------|
| ESCALATION_MISSED   | Predicted low/stable but observed significant escalation |
| FALSE_ESCALATION    | Predicted escalation but observed stability/decline |
| MAGNITUDE_SHIFT     | Direction correct but magnitude significantly off |

## Trust Adjustment Mechanism

The trust adjustment is the **only synthetic input** to the pipeline re-execution:

```
forecast_error_penalty = min(0.30, mean_scaled_deviation × 0.10)
adjusted_trust = max(0.05, prior_trust - forecast_error_penalty)
```

**Rationale**: A forecast that was significantly wrong has empirically
demonstrated lower reliability. The trust framework is designed to
represent model reliability, so adjusting trust based on forecast error
is semantically appropriate.

The actual magnitude of risk/priority/response changes is determined
entirely by the existing pipeline logic operating on this adjusted trust,
not by the reconsideration engine.

## Safety Invariants

1. **`requires_human = True` always.** Every `ReconsiderationEvent` has
   `requires_human=True`. Attempting to construct one with `False` raises
   `ValueError`.

2. **No destructive autonomy.** Reconsideration may revise risk scores,
   stage hypotheses, and recommendations, but never bypasses human approval.

3. **Single current truth.** When reconsideration produces a revision, the
   `DemoEvent` emitted to the UI carries the revised assessment. There are
   never two contradictory "current truths."

4. **Audit trail.** Every `ReconsiderationEvent` contains:
   - Prior assessment snapshot
   - Conflict evidence with per-feature deviations
   - Revised assessment from pipeline re-execution
   - Revision magnitude and type
   - Deterministic SHA-256 provenance hash

## Limitations

1. **Single-step lookback (depth=1).** Reconsideration compares the current
   step against the most recent prior step only. Multi-step revision chains
   are not implemented. The `lookback_depth` parameter is configurable for
   future extension.

2. **Not retroactive.** Reconsideration does not revise historical database
   entries. It produces a forward-looking revised assessment for the current
   step.

3. **Trust is the only lever.** The reconsideration engine does not modify
   feature values, model coefficients, or threshold parameters. It only
   adjusts the trust input to the existing pipeline.

4. **Depends on forecast quality.** If the AR(5) model always predicts
   near-zero deltas (e.g., untrained dummy model), reconsideration may
   trigger more frequently than operationally meaningful. In production,
   the trained model produces meaningful predictions.

## Files

| File | Role |
|------|------|
| `security/reconsideration.py` | Data models (EvidenceConflict, ReconsiderationEvent) and ReconsiderationEngine |
| `scenarios/demo/engine.py` | Pipeline integration: reconsideration in stream_scenario() loop |
| `runtime/demo_adapter.py` | RECONSIDERATION SSE message type |
| `tests/test_reconsideration.py` | 15 unit/integration tests |
| `docs/RECONSIDERATION_ARCHITECTURE.md` | This document |
