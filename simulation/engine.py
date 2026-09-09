"""Intervention Simulator Engine for Phase 3A: Bounded Simulation (SIH 26153).

Coordinates:
- Baseline AR(5) multi-step forecast rollout
- Deterministic hypothetical InterventionOperator
- Existing BehavioralSecurityBridge signature extraction
- Existing SecurityRiskEngine risk trajectory evaluation
- Comparative trajectory evaluation and risk reduction analysis

SAFETY GUARANTEE:
This engine is SIMULATION ONLY.
NO real network actions are executed.
NO response execution adapters are ever invoked.
DO NOT modify frozen AR(5) or SecurityRiskEngine components.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
from typing import Mapping, Sequence

import numpy as np

from core.contracts import (
    STATE_SCHEMA_HASH,
    Direction,
    Forecast,
    NetworkState,
    Trajectory,
    TrajectoryStep,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    new_id,
)
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.metrics_v2 import RobustScaleStatistics
from eval.rollout import MultiStepRolloutEngine
from security.bridge import BehavioralSecurityBridge
from security.contracts import FutureSecurityRiskScore, SecurityRiskTrajectory
from security.risk_engine import SecurityRiskEngine
from simulation.models import (
    AssumptionRecord,
    InterventionParameters,
    InterventionStatus,
    InterventionType,
    SimulationResult,
)
from simulation.operator import InterventionOperator


class InterventionSimulator:
    """
    Simulates hypothetical interventions applied to short-horizon forecast trajectories.
    Pure comparative evaluation layer: does not execute, optimize, or alter production state.
    """

    def __init__(
        self,
        bridge: BehavioralSecurityBridge | None = None,
        risk_engine: SecurityRiskEngine | None = None,
        rollout_engine: MultiStepRolloutEngine | None = None,
        feature_names: Sequence[str] | None = None,
        scales: RobustScaleStatistics | None = None,
        model_id: str = "AR_p5_Simulation",
    ) -> None:
        self.feature_names = list(feature_names) if feature_names is not None else list(CSV_AVAILABLE_FEATURES)
        self.scales = scales
        self.model_id = model_id
        self.bridge = bridge if bridge is not None else BehavioralSecurityBridge(scales=self.scales)
        self.risk_engine = risk_engine if risk_engine is not None else SecurityRiskEngine()
        self.rollout_engine = rollout_engine

    def simulate(
        self,
        current_state: NetworkState,
        action: InterventionType,
        params: InterventionParameters | None = None,
        history_deltas: np.ndarray | None = None,
        baseline_deltas: np.ndarray | None = None,
        trust_assessment: TrustAssessment | None = None,
        max_horizon: int = 3,
    ) -> SimulationResult:
        """
        Execute bounded intervention-conditioned simulation for a candidate action.

        Args:
            current_state: Observed NetworkState (NEVER mutated).
            action: Candidate InterventionType to hypothetically apply.
            params: Configurable InterventionParameters (defaults to standard design parameters).
            history_deltas: Optional (1, 5 * D) array of historical deltas for AR(5) rollout.
            baseline_deltas: Optional (H, D) array of pre-computed baseline deltas.
            trust_assessment: Optional TrustAssessment (synthesizes default high-trust if omitted).
            max_horizon: Lookahead steps (default 3, corresponding to +10s, +20s, +30s).

        Returns:
            SimulationResult containing baseline vs intervention comparative trajectories,
            risk trajectories, explicit assumptions, and uncertainty metrics.
        """
        if params is None:
            params = InterventionParameters()

        n_feats = len(self.feature_names)

        # ── 1. Obtain Baseline Deltas ──
        if baseline_deltas is not None:
            b_deltas = np.array(baseline_deltas, dtype=np.float64)
            if b_deltas.ndim == 3 and b_deltas.shape[0] == 1:
                b_deltas = b_deltas[0]
            if b_deltas.shape != (max_horizon, n_feats):
                raise ValueError(f"baseline_deltas shape {b_deltas.shape} must be ({max_horizon}, {n_feats})")
        else:
            if self.rollout_engine is None or history_deltas is None:
                raise ValueError("Must provide either baseline_deltas or both rollout_engine and history_deltas")
            curr_vals = current_state.feature_values()
            curr_vec = np.array([[curr_vals.get(f, 0.0) for f in self.feature_names]], dtype=np.float64)
            pred_deltas, _ = self.rollout_engine.forecast_open_loop(history_deltas, curr_vec, max_horizon=max_horizon)
            b_deltas = pred_deltas[0]

        # Invariant: Ensure input baseline deltas are immutable
        b_deltas_clean = b_deltas.copy()

        # ── 2. Apply Hypothetical Intervention Operator ──
        (
            int_deltas,
            assumptions,
            warnings,
            status,
            intervention_unc,
        ) = InterventionOperator.apply(
            current_state=current_state,
            baseline_deltas=b_deltas_clean,
            feature_names=self.feature_names,
            action=action,
            params=params,
        )

        # ── 3. Establish Trust Context ──
        if trust_assessment is None:
            trust_assessment = TrustAssessment(
                assessment_id=new_id("trust-sim"),
                forecast_id=f"fc-sim-{current_state.window_id[:8]}",
                forecast_confidence=0.85,
                model_disagreement=0.05,
                distribution_shift_score=0.05,
                novelty_score=0.05,
                historical_error=0.10,
                data_quality=current_state.data_quality,
                composite_trust=0.85,
                trust_level=TrustLevel.HIGH,
                contributing_factors=(
                    TrustFactor(name="simulation_default", value=0.85, direction=Direction.INCREASES_TRUST),
                ),
            )

        trust_lvl = trust_assessment.trust_level

        # ── 4. Evaluate Baseline Security Signatures, Hypotheses & Risk ──
        base_sigs = self.bridge.extract_signatures(
            current_state,
            forecast_deltas=b_deltas_clean,
            feature_names=self.feature_names,
            trust_level=trust_lvl,
            uncertainty=0.20,
        )
        base_hyps = self.bridge.infer_stage_hypotheses(base_sigs, trust_level=trust_lvl)
        base_risk_traj = self.risk_engine.compute_risk_trajectory(
            current_state=current_state,
            stage_hypotheses=base_hyps,
            trust_assessment=trust_assessment,
            signatures=base_sigs,
            max_horizon=max_horizon,
        )

        # ── 5. Evaluate Intervention Security Signatures, Hypotheses & Risk ──
        int_sigs = self.bridge.extract_signatures(
            current_state,
            forecast_deltas=int_deltas,
            feature_names=self.feature_names,
            trust_level=trust_lvl,
            uncertainty=0.20,
        )
        int_hyps = self.bridge.infer_stage_hypotheses(int_sigs, trust_level=trust_lvl)
        int_risk_traj = self.risk_engine.compute_risk_trajectory(
            current_state=current_state,
            stage_hypotheses=int_hyps,
            trust_assessment=trust_assessment,
            signatures=int_sigs,
            max_horizon=max_horizon,
        )

        # ── 6. Construct Valid Core Contracts Trajectories ──
        now = datetime.now()
        base_traj = self._build_trajectory(
            current_state=current_state,
            deltas=b_deltas_clean,
            max_horizon=max_horizon,
            traj_prefix="traj-baseline",
            created_at=now,
        )
        int_traj = self._build_trajectory(
            current_state=current_state,
            deltas=int_deltas,
            max_horizon=max_horizon,
            traj_prefix=f"traj-int-{action.value.lower()}",
            created_at=now,
        )

        # ── 7. Comparative Metrics ──
        base_all_risks = [base_risk_traj.current_risk.score] + [fr.score for fr in base_risk_traj.future_risks]
        int_all_risks = [int_risk_traj.current_risk.score] + [fr.score for fr in int_risk_traj.future_risks]

        peak_base_risk = max(base_all_risks)
        peak_int_risk = max(int_all_risks)
        risk_delta = peak_int_risk - peak_base_risk
        risk_reduction = max(0.0, peak_base_risk - peak_int_risk)

        horizon_deltas: dict[int, float] = {
            0: int_risk_traj.current_risk.score - base_risk_traj.current_risk.score
        }
        for h_idx in range(len(base_risk_traj.future_risks)):
            h_step = base_risk_traj.future_risks[h_idx].horizon_step
            horizon_deltas[h_step] = int_risk_traj.future_risks[h_idx].score - base_risk_traj.future_risks[h_idx].score

        # Explicit forecast uncertainty preservation
        forecast_unc: dict[int, float] = {
            0: base_risk_traj.current_risk.uncertainty
        }
        for fr in base_risk_traj.future_risks:
            forecast_unc[fr.horizon_step] = fr.uncertainty

        # Provenance hash
        hash_str = (
            f"{current_state.window_id}:{action.value}:{status.value}:"
            f"{base_risk_traj.current_risk.provenance_hash}:{int_risk_traj.current_risk.provenance_hash}:"
            f"{peak_base_risk:.4f}:{peak_int_risk:.4f}:{risk_delta:.4f}"
        )
        prov_hash = hashlib.sha256(hash_str.encode("utf-8")).hexdigest()

        return SimulationResult(
            action=action,
            status=status,
            baseline_trajectory=base_traj,
            intervention_trajectory=int_traj,
            baseline_risk=base_risk_traj,
            intervention_risk=int_risk_traj,
            risk_delta=risk_delta,
            risk_reduction=risk_reduction,
            peak_baseline_risk=peak_base_risk,
            peak_intervention_risk=peak_int_risk,
            horizon_risk_deltas=horizon_deltas,
            assumptions=assumptions,
            warnings=warnings,
            forecast_uncertainty=forecast_unc,
            intervention_uncertainty=intervention_unc,
            provenance_hash=prov_hash,
            created_at=now,
        )

    def _build_trajectory(
        self,
        current_state: NetworkState,
        deltas: np.ndarray,
        max_horizon: int,
        traj_prefix: str,
        created_at: datetime,
    ) -> Trajectory:
        """Construct an immutable Trajectory meeting all core/contracts.py invariants."""
        src_vals = current_state.feature_values()
        curr_state = dict(src_vals)
        steps: list[TrajectoryStep] = []

        for h in range(max_horizon):
            step_delta = {f: float(deltas[h, j]) for j, f in enumerate(self.feature_names)}
            step_state = {f: curr_state[f] + step_delta[f] for f in self.feature_names}

            fc = Forecast(
                forecast_id=new_id("fc-sim"),
                source_state_id=current_state.window_id,
                target_timestamp=current_state.timestamp_end + timedelta(seconds=10 * (h + 1)),
                horizon_steps=h + 1,
                delta_predicted=step_delta,
                state_predicted=step_state,
                model_id=self.model_id,
                model_version="phase3a-sim-v1",
                feature_schema_hash=STATE_SCHEMA_HASH,
                created_at=created_at,
            )
            steps.append(TrajectoryStep(step_index=h, forecast=fc))
            curr_state = step_state

        return Trajectory(
            trajectory_id=new_id(traj_prefix),
            parent_state_id=current_state.window_id,
            steps=tuple(steps),
            weight=1.0,
            cumulative_error=None,
            is_active=True,
            pruned_reason=None,
            created_at=created_at,
            last_updated=created_at,
        )
