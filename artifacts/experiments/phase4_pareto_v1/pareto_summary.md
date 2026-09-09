# Phase 4 Experiment A — Response Pareto Frontier Summary

- **Experiment ID**: `phase4_pareto_v1`
- **Git Commit SHA**: `7ec690bbc997e47ea501f5b33b04ea2490e9d584` (Dirty: `True`)
- **Experiment Seed**: `42`
- **Fidelity Disclosure**: `PARAMETERIZED_STATE_TRANSFORMATION_NOT_HARDWARE_INLINE`
- **Telemetry Source**: `SYNTHETIC_CONTROLLED_SCENARIO`
- **Epistemic Status**: `OBSERVATIONAL_TRAJECTORY_VERIFICATION_NON_PEARLIAN`
- **Scenarios Evaluated**: 12
- **Relative Disruption Reduction (Point Estimate)**: **100.00%** (95% CI: [100.00%, 100.00%])
- **Absolute Disruption Difference**: **0.0125** (95% CI: [0.0083, 0.0167])
- **Predefined Target**: $\ge 30.0\%$ relative reduction
- **Scientific Verdict**: **SUPPORT**
- **Paired Wilcoxon Signed-Rank Test p-value**: 0.001953
- **Cliff's Delta Effect Size**: 0.7500
- **True Safety Envelope Satisfaction Rate**: **83.3%** (10/12 scenarios)
- **Scenarios with NO_SUFFICIENT_ACTION**: 2 (properly excluded from safety envelope satisfaction)

### Baseline Hierarchy Overview
- **B0**: Null Defender (`DO_NOTHING`)
- **B1**: Reactive Sledgehammer (`TEMPORARY_BLOCK_IP` upon threshold trip)
- **B2**: Static Playbook (`RATE_LIMIT_IP` upon threshold trip)
- **B3**: Forecast Alert Only (Forecast warning, action `DO_NOTHING`)
- **B4**: Forecast + Fixed Action (Forecast alert triggers `RATE_LIMIT_IP`)
- **B5**: Full Predictive System (Phase 3B Minimum-Sufficient Selection)

### Scenario Trade-off Breakdown
| Scenario | Attack? | B1 Action | B1 Disrupt | B2 Disrupt | B4 Disrupt | B5 Action | B5 Disrupt | B5 vs B1 Red. | B5 Safe? |
|---|---|---|---|---|---|---|---|---|---|
| `recon_slow_port_scan` | Yes | `TEMPORARY_BLOCK_IP` | 0.017 | 0.004 | 0.004 | `DO_NOTHING` | 0.000 | 100.0% | YES |
| `recon_stepping_stone` | Yes | `TEMPORARY_BLOCK_IP` | 0.017 | 0.004 | 0.004 | `DO_NOTHING` | 0.000 | 100.0% | YES |
| `recon_rapid_syn_probe` | Yes | `TEMPORARY_BLOCK_IP` | 0.017 | 0.004 | 0.004 | `DO_NOTHING` | 0.000 | 100.0% | YES |
| `dos_gradual_syn_ramp` | Yes | `TEMPORARY_BLOCK_IP` | 0.017 | 0.004 | 0.004 | `DO_NOTHING` | 0.000 | 100.0% | YES |
| `dos_connection_exhaustion` | Yes | `TEMPORARY_BLOCK_IP` | 0.017 | 0.004 | 0.004 | `NO_SUFFICIENT_ACTION` | 0.000 | 100.0% | NO |
| `dos_volumetric_udp_flood` | Yes | `TEMPORARY_BLOCK_IP` | 0.017 | 0.004 | 0.004 | `NO_SUFFICIENT_ACTION` | 0.000 | 100.0% | NO |
| `exfil_dns_tunneling` | Yes | `TEMPORARY_BLOCK_IP` | 0.017 | 0.004 | 0.004 | `DO_NOTHING` | 0.000 | 100.0% | YES |
| `exfil_volumetric_tcp` | Yes | `TEMPORARY_BLOCK_IP` | 0.017 | 0.004 | 0.004 | `DO_NOTHING` | 0.000 | 100.0% | YES |
| `exfil_burst_web` | Yes | `TEMPORARY_BLOCK_IP` | 0.017 | 0.004 | 0.004 | `DO_NOTHING` | 0.000 | 100.0% | YES |
| `benign_backup_surge` | No | `DO_NOTHING` | 0.000 | 0.000 | 0.000 | `DO_NOTHING` | 0.000 | 0.0% | YES |
| `benign_flash_crowd` | No | `DO_NOTHING` | 0.000 | 0.000 | 0.000 | `DO_NOTHING` | 0.000 | 0.0% | YES |
| `benign_ambiguous_noise` | No | `DO_NOTHING` | 0.000 | 0.000 | 0.000 | `DO_NOTHING` | 0.000 | 0.0% | YES |
