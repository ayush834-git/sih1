# Experiment D: Closed-Loop Multi-Window Stability Summary

- **Git Commit SHA**: `7ec690bbc997e47ea501f5b33b04ea2490e9d584` (Dirty: `True`)
- **Experiment Seed**: `42`
- **Fidelity Disclosure**: `PARAMETERIZED_STATE_TRANSFORMATION_NOT_HARDWARE_INLINE`
- **Telemetry Source**: `SYNTHETIC_CONTROLLED_SCENARIO`
- **Total Windows Evaluated**: 60 (600 seconds of continuous traffic)
- **All Action Transition Rate**: **0.0169**
- **Nontrivial Flapping Rate**: **0.0000** (Predefined Target: <= 0.05)
- **Scientific Verdict**: **SUPPORT**
- **Trust Recovery Status**: `NOT CURRENTLY IMPLEMENTED / NOT APPLICABLE`
- **Autonomous Second Executions (N_auto_exec)**: **0**
- **Autonomous Rollbacks (N_auto_rollback)**: **0**
- **Reconsideration Requests**: 0 (All approval_required=True)

### Trajectory Phase Breakdown
1. Windows 0..9: Benign Baseline (NO_ACTION, Flap=0)
2. Windows 10..19: Recon Escalation -> Human-approved TEMP_RATE_LIMIT
3. Windows 20..29: Active Mitigation & Trajectory Conformance
4. Windows 30..39: Injected Vector Mutation -> VERIFIED_MISMATCH Detected
5. Windows 40..49: Reconsidered Human-approved DEMO_BLOCK -> Stabilization
6. Windows 50..59: Return to Steady-State Baseline Telemetry
