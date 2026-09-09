# Experiment C: Contradiction / Model Mismatch Summary

- **Git Commit SHA**: `7ec690bbc997e47ea501f5b33b04ea2490e9d584` (Dirty: `True`)
- **Experiment Seed**: `42`
- **Injected Divergence Detection Rate**: **100.0%** (3/3 modes)
- **Conforming False Mismatch Rate**: **0.0%** (Denominator: 1 conforming mode)
- **Sensor Blackout Outcome**: `INSUFFICIENT_EVIDENCE` (fails closed, 0 false triggers)
- **Autonomous Execution Calls**: **0**
- **Autonomous Rollback Calls**: **0**

| Mode | Condition | Outcome | Reconsideration | Human Approval Required | Auto-Exec Calls |
| --- | --- | --- | --- | --- | --- |
| Mode 0 (Conforming Control) | Expected VERIFIED_SUCCESS | **VERIFIED_SUCCESS** | None | N/A | 0 |
| Mode 1 (Vector Mutation) | Expected VERIFIED_MISMATCH | **VERIFIED_MISMATCH** | Triggered | YES | 0 |
| Mode 2 (Volumetric Overpower) | Expected VERIFIED_MISMATCH | **VERIFIED_MISMATCH** | Triggered | YES | 0 |
| Mode 3 (Benign Surge) | Expected VERIFIED_MISMATCH | **VERIFIED_MISMATCH** | Triggered | YES | 0 |
| Mode 4 (Sensor Blackout) | Expected INSUFFICIENT_EVIDENCE | **INSUFFICIENT_EVIDENCE** | None | N/A | 0 |
