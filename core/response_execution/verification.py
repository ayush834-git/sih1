"""Outcome Verification Layer (SIH 26153 Task 21).

Provides:
- OutcomeExpectation and VerificationStatus
- OutcomeVerificationResult with deterministic SHA-256 provenance
- OutcomeMismatchHandoff bridging verification conflict into Task 17 Reconsideration
- OutcomeVerifier engine

CRITICAL INVARIANTS:
1. EXECUTED != VERIFIED_SUCCESS.
2. Missing or low-quality telemetry NEVER implies success (fails closed to INSUFFICIENT_EVIDENCE).
3. Outcome mismatch NEVER fabricates a synthetic revised risk score directly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from hashlib import sha256
from typing import Any, Mapping, Sequence

from core.contracts import FeatureAvailability, NetworkState, new_id
from core.response_execution.models import ResponseAction


class VerificationStatus(str, Enum):
    """
    Explicit status of an outcome verification assessment.
    """
    VERIFIED_SUCCESS = "VERIFIED_SUCCESS"         # Observed telemetry confirms expected outcome.
    VERIFIED_MISMATCH = "VERIFIED_MISMATCH"       # Observed telemetry contradicts or fails expected outcome.
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE" # Telemetry missing, unmeasured, or degraded; cannot verify.
    NOT_VERIFIABLE = "NOT_VERIFIABLE"             # Action has no quantitative telemetry expectation.


@dataclass(frozen=True)
class OutcomeExpectation:
    """
    Defines what constitutes operational success for a response action.
    """
    action_id: str
    metric_name: str                              # Feature name, e.g. "byte_rate", "flow_count", "syn_ratio"
    expected_direction: str                       # "DECREASE", "INCREASE", "BELOW_THRESHOLD"
    baseline_value: float                         # Pre-action baseline measurement
    target_threshold: float | None = None         # Absolute target if applicable
    min_reduction_ratio: float | None = None      # e.g. 0.20 = expect >= 20% reduction
    verification_window_steps: int = 1
    tolerance: float = 0.05

    def __post_init__(self) -> None:
        if not self.action_id:
            raise ValueError("action_id is required")
        if not self.metric_name:
            raise ValueError("metric_name is required")
        if self.expected_direction not in ("DECREASE", "INCREASE", "BELOW_THRESHOLD"):
            raise ValueError(f"Unsupported expected_direction: {self.expected_direction}")


@dataclass(frozen=True)
class OutcomeMismatchHandoff:
    """
    Structured handoff payload generated when an outcome mismatch is verified.
    Prepares auditable evidence for Task 17 Reconsideration.
    CRITICAL: Does NOT fabricate a revised risk score.
    """
    action_id: str
    evidence_window_id: str
    metric_name: str
    baseline_value: float
    observed_value: float
    expected_effect: str
    observed_effect: str
    conflict_summary: str
    provenance_hash: str
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "evidence_window_id": self.evidence_window_id,
            "metric_name": self.metric_name,
            "baseline_value": round(self.baseline_value, 4),
            "observed_value": round(self.observed_value, 4),
            "expected_effect": self.expected_effect,
            "observed_effect": self.observed_effect,
            "conflict_summary": self.conflict_summary,
            "provenance_hash": self.provenance_hash,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class OutcomeVerificationResult:
    """
    Immutable audit record of an outcome verification assessment.
    """
    verification_id: str
    action_id: str
    status: VerificationStatus
    metric_name: str
    baseline_value: float
    observed_value: float | None
    expected_description: str
    observed_description: str
    deviation: float | None = None
    evidence_window_id: str | None = None
    reconsideration_recommended: bool = False
    explanation: str = ""
    provenance_hash: str = field(default="")
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self) -> None:
        if not self.verification_id:
            raise ValueError("verification_id is required")
        if not self.action_id:
            raise ValueError("action_id is required")

        if not self.provenance_hash:
            obs_str = f"{self.observed_value:.4f}" if self.observed_value is not None else "NONE"
            dev_str = f"{self.deviation:.4f}" if self.deviation is not None else "NONE"
            canonical_repr = (
                f"{self.verification_id}|{self.action_id}|{self.status.value}|"
                f"{self.metric_name}|{self.baseline_value:.4f}|{obs_str}|{dev_str}|"
                f"{self.reconsideration_recommended}"
            )
            object.__setattr__(self, "provenance_hash", sha256(canonical_repr.encode("utf-8")).hexdigest())

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "action_id": self.action_id,
            "status": self.status.value,
            "metric_name": self.metric_name,
            "baseline_value": round(self.baseline_value, 4),
            "observed_value": round(self.observed_value, 4) if self.observed_value is not None else None,
            "deviation": round(self.deviation, 4) if self.deviation is not None else None,
            "expected_description": self.expected_description,
            "observed_description": self.observed_description,
            "evidence_window_id": self.evidence_window_id,
            "reconsideration_recommended": self.reconsideration_recommended,
            "explanation": self.explanation,
            "provenance_hash": self.provenance_hash,
            "created_at": self.created_at.isoformat(),
        }


class OutcomeVerifier:
    """
    Evaluates whether observed post-action telemetry confirms expected response effects.
    """

    def verify(
        self,
        action: ResponseAction,
        expectation: OutcomeExpectation,
        observed_state: NetworkState | Mapping[str, Any],
    ) -> OutcomeVerificationResult:
        """
        Compare observed telemetry against expectation.
        Fails closed to INSUFFICIENT_EVIDENCE if telemetry is missing or unmeasured.
        """
        verification_id = new_id("verif")
        window_id = getattr(observed_state, "window_id", None)
        if isinstance(observed_state, dict) and "window_id" in observed_state:
            window_id = str(observed_state["window_id"])

        # 1. Extract observed feature value
        observed_val: float | None = None
        if isinstance(observed_state, NetworkState):
            # Check availability
            avail = observed_state.feature_availability.get(expectation.metric_name, FeatureAvailability.AVAILABLE)
            if avail != FeatureAvailability.AVAILABLE or observed_state.is_empty:
                return OutcomeVerificationResult(
                    verification_id=verification_id,
                    action_id=action.action_id,
                    status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                    metric_name=expectation.metric_name,
                    baseline_value=expectation.baseline_value,
                    observed_value=None,
                    expected_description=f"Expect {expectation.expected_direction} on {expectation.metric_name}",
                    observed_description="Telemetry unavailable or empty window",
                    evidence_window_id=window_id,
                    explanation=(
                        f"Cannot verify action '{action.action_id}': metric '{expectation.metric_name}' "
                        f"is {avail.value} in window '{window_id}'. Missing evidence never implies success."
                    ),
                )
            raw_val = getattr(observed_state, expectation.metric_name, None)
            if raw_val is not None:
                observed_val = float(raw_val)
        elif isinstance(observed_state, dict):
            if expectation.metric_name in observed_state:
                raw_val = observed_state[expectation.metric_name]
                if raw_val is not None:
                    observed_val = float(raw_val)

        if observed_val is None:
            return OutcomeVerificationResult(
                verification_id=verification_id,
                action_id=action.action_id,
                status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                metric_name=expectation.metric_name,
                baseline_value=expectation.baseline_value,
                observed_value=None,
                expected_description=f"Expect {expectation.expected_direction} on {expectation.metric_name}",
                observed_description="Telemetry metric missing from observation payload",
                evidence_window_id=window_id,
                explanation=f"Telemetry metric '{expectation.metric_name}' was not found in observed state.",
            )

        # 2. Evaluate quantitative difference
        base = expectation.baseline_value
        obs = observed_val
        status = VerificationStatus.VERIFIED_MISMATCH
        reconsideration_recommended = False
        deviation = obs - base

        if expectation.expected_direction == "DECREASE":
            min_reduction = expectation.min_reduction_ratio if expectation.min_reduction_ratio is not None else 0.10
            actual_reduction_ratio = (base - obs) / max(1e-6, abs(base))
            if actual_reduction_ratio >= (min_reduction - expectation.tolerance):
                status = VerificationStatus.VERIFIED_SUCCESS
                reconsideration_recommended = False
                explanation = (
                    f"Action '{action.action_id}' VERIFIED SUCCESS: {expectation.metric_name} dropped from "
                    f"{base:.2f} to {obs:.2f} (reduction ratio: {actual_reduction_ratio*100:.1f}%, target: >={min_reduction*100:.1f}%)."
                )
            else:
                status = VerificationStatus.VERIFIED_MISMATCH
                reconsideration_recommended = True
                explanation = (
                    f"Action '{action.action_id}' VERIFIED MISMATCH: {expectation.metric_name} did not exhibit expected drop. "
                    f"Baseline={base:.2f}, Observed={obs:.2f} (reduction ratio: {actual_reduction_ratio*100:.1f}%, target: >={min_reduction*100:.1f}%). "
                    "New observation conflicts with expected response effect; reconsideration recommended."
                )

        elif expectation.expected_direction == "BELOW_THRESHOLD":
            thresh = expectation.target_threshold if expectation.target_threshold is not None else base * 0.5
            if obs <= (thresh + expectation.tolerance):
                status = VerificationStatus.VERIFIED_SUCCESS
                reconsideration_recommended = False
                explanation = f"Action '{action.action_id}' VERIFIED SUCCESS: {expectation.metric_name} is {obs:.2f} (<= target {thresh:.2f})."
            else:
                status = VerificationStatus.VERIFIED_MISMATCH
                reconsideration_recommended = True
                explanation = (
                    f"Action '{action.action_id}' VERIFIED MISMATCH: {expectation.metric_name} is {obs:.2f} (> target {thresh:.2f}). "
                    "Reconsideration recommended."
                )

        elif expectation.expected_direction == "INCREASE":
            min_inc = expectation.min_reduction_ratio if expectation.min_reduction_ratio is not None else 0.10
            actual_increase_ratio = (obs - base) / max(1e-6, abs(base))
            if actual_increase_ratio >= (min_inc - expectation.tolerance):
                status = VerificationStatus.VERIFIED_SUCCESS
                reconsideration_recommended = False
                explanation = f"Action '{action.action_id}' VERIFIED SUCCESS: {expectation.metric_name} increased from {base:.2f} to {obs:.2f}."
            else:
                status = VerificationStatus.VERIFIED_MISMATCH
                reconsideration_recommended = True
                explanation = f"Action '{action.action_id}' VERIFIED MISMATCH: {expectation.metric_name} did not exhibit expected increase."

        return OutcomeVerificationResult(
            verification_id=verification_id,
            action_id=action.action_id,
            status=status,
            metric_name=expectation.metric_name,
            baseline_value=base,
            observed_value=obs,
            deviation=deviation,
            expected_description=f"Expect {expectation.expected_direction} from baseline {base:.2f}",
            observed_description=f"Observed value {obs:.2f} (delta {deviation:+.2f})",
            evidence_window_id=window_id,
            reconsideration_recommended=reconsideration_recommended,
            explanation=explanation,
        )

    def build_reconsideration_handoff(
        self,
        result: OutcomeVerificationResult,
    ) -> OutcomeMismatchHandoff | None:
        """
        Build an auditable handoff record when verification detects an outcome mismatch.
        Prepares clean conflict evidence for Task 17 Reconsideration without fabricating risk.
        """
        if result.status != VerificationStatus.VERIFIED_MISMATCH:
            return None

        hash_payload = (
            f"{result.action_id}:{result.metric_name}:{result.baseline_value:.4f}:"
            f"{result.observed_value}:{result.evidence_window_id}"
        )
        prov_hash = sha256(hash_payload.encode("utf-8")).hexdigest()

        return OutcomeMismatchHandoff(
            action_id=result.action_id,
            evidence_window_id=result.evidence_window_id or "unknown-window",
            metric_name=result.metric_name,
            baseline_value=result.baseline_value,
            observed_value=result.observed_value if result.observed_value is not None else 0.0,
            expected_effect=result.expected_description,
            observed_effect=result.observed_description,
            conflict_summary=(
                f"Defensive action '{result.action_id}' failed to produce expected {result.metric_name} reduction. "
                f"Baseline: {result.baseline_value:.2f}, Observed: {result.observed_value}."
            ),
            provenance_hash=prov_hash,
        )

    def verify_trajectory(
        self,
        action: ResponseAction,
        expectation: TrajectoryOutcomeExpectation,
        observed_states: Sequence[NetworkState] | NetworkState,
        risk_engine: Any = None,
        bridge: Any = None,
        config: TrajectoryVerificationConfig | None = None,
    ) -> TrajectoryVerificationResult:
        """
        Evaluate observed post-action telemetry against a Phase 3A simulated intervention trajectory.
        Enforces execution-relative window alignment, action TTL boundaries, uncertainty tolerance cones,
        and persistence requirements.
        """
        cfg = config or TrajectoryVerificationConfig()
        verification_id = new_id("verif-traj")

        # 1. Normalize observed states into sequence
        raw_states = [observed_states] if isinstance(observed_states, NetworkState) else list(observed_states)

        # 2. Deterministic execution-relative window alignment:
        # Filter candidate states to those strictly following the execution window
        candidate_states: list[NetworkState] = []
        for s in raw_states:
            if not isinstance(s, NetworkState):
                continue
            if expectation.execution_window_id and s.window_id == expectation.execution_window_id:
                continue
            if expectation.execution_timestamp_end is not None and s.timestamp_start < expectation.execution_timestamp_end:
                continue
            candidate_states.append(s)

        candidate_states.sort(key=lambda x: x.timestamp_start)

        # 3. Check for missing or empty telemetry -> INSUFFICIENT_EVIDENCE
        if not candidate_states:
            return TrajectoryVerificationResult(
                verification_id=verification_id,
                action_id=action.action_id,
                status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                step_evaluations={},
                max_observed_risk=None,
                risk_ceiling=expectation.risk_ceiling,
                risk_ceiling_breached=False,
                persistence_count=0,
                reconsideration_recommended=False,
                explanation="No post-execution observation windows available; fails closed.",
                evidence_window_ids=(),
            )

        if candidate_states[0].is_empty:
            return TrajectoryVerificationResult(
                verification_id=verification_id,
                action_id=action.action_id,
                status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                step_evaluations={},
                max_observed_risk=None,
                risk_ceiling=expectation.risk_ceiling,
                risk_ceiling_breached=False,
                persistence_count=0,
                reconsideration_recommended=False,
                explanation=(
                    f"Observation window '{candidate_states[0].window_id}' is empty or degraded. "
                    "Missing evidence never implies success."
                ),
                evidence_window_ids=(candidate_states[0].window_id,),
            )

        # 4. Action TTL Boundary Partitioning:
        # Only fully covered observation windows within the active action TTL interval count as active-intervention evidence.
        t_expire = expectation.execution_timestamp_end + timedelta(seconds=expectation.action_ttl_seconds)
        active_states: list[NetworkState] = []
        for s in candidate_states:
            if s.timestamp_end <= (t_expire + timedelta(seconds=1.0)):
                active_states.append(s)

        if not active_states:
            return TrajectoryVerificationResult(
                verification_id=verification_id,
                action_id=action.action_id,
                status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                step_evaluations={},
                max_observed_risk=None,
                risk_ceiling=expectation.risk_ceiling,
                risk_ceiling_breached=False,
                persistence_count=0,
                reconsideration_recommended=False,
                explanation="All candidate observation windows lie beyond active action TTL; post-expiration recovery.",
                evidence_window_ids=tuple(s.window_id for s in candidate_states),
            )

        # 5. Horizon evaluation across lookahead steps
        eval_states = active_states[:cfg.max_observation_steps]
        step_evals: dict[int, dict[str, Any]] = {}
        observed_risks: list[float] = []
        consecutive_mismatches = 0
        max_consecutive_mismatches = 0
        ceiling_breached = False

        # Identify primary feature to evaluate
        primary_feature = "byte_rate"
        for f in expectation.target_features:
            avail = eval_states[0].feature_availability.get(f, FeatureAvailability.AVAILABLE)
            if avail == FeatureAvailability.AVAILABLE and getattr(eval_states[0], f, None) is not None:
                primary_feature = f
                break

        baseline_val = float(getattr(expectation.baseline_state, primary_feature, 0.0) or 0.0)

        for i, st in enumerate(eval_states):
            h = i + 1
            # Uncertainty-expanded tolerance formula: Tolerance(h) = Base * (1 + kappa * (h - 1))
            step_tolerance = cfg.base_tolerance * (1.0 + cfg.horizon_expansion_factor * (h - 1))
            obs_val = float(getattr(st, primary_feature, 0.0) or 0.0)
            obs_delta = obs_val - baseline_val

            # Layer 1: Security Risk Ceiling Constraint
            step_risk: float | None = None
            step_risk_breached = False
            if risk_engine is not None and bridge is not None:
                try:
                    sigs = bridge.extract_signatures(st)
                    hyps = bridge.infer_stage_hypotheses(sigs, st)
                    primary_hyp = hyps[0] if hyps else None
                    if primary_hyp is not None:
                        risk_score_obj = risk_engine.compute_risk_score(st, primary_hyp, horizon_step=0)
                        step_risk = float(risk_score_obj.score)
                        observed_risks.append(step_risk)
                        if step_risk > expectation.risk_ceiling:
                            step_risk_breached = True
                            ceiling_breached = True
                except Exception:
                    step_risk = None

            # Layer 2: Feature Delta Direction & Tolerance
            feature_diverged = False
            if baseline_val > 0:
                if (obs_val - baseline_val) / max(1.0, baseline_val) > step_tolerance:
                    feature_diverged = True
            elif obs_val > 1000.0:
                feature_diverged = True

            step_mismatch = step_risk_breached or feature_diverged
            if step_mismatch:
                consecutive_mismatches += 1
                max_consecutive_mismatches = max(max_consecutive_mismatches, consecutive_mismatches)
            else:
                consecutive_mismatches = 0

            step_evals[h] = {
                "window_id": st.window_id,
                "horizon_step": h,
                "step_tolerance": round(step_tolerance, 4),
                "primary_feature": primary_feature,
                "baseline_value": round(baseline_val, 2),
                "observed_value": round(obs_val, 2),
                "observed_delta": round(obs_delta, 2),
                "observed_risk": round(step_risk, 4) if step_risk is not None else None,
                "risk_ceiling_breached": step_risk_breached,
                "feature_diverged": feature_diverged,
                "step_mismatch": step_mismatch,
            }

        max_risk = max(observed_risks) if observed_risks else None

        # 6. Persistence & Final Classification
        is_mismatch = ceiling_breached or (max_consecutive_mismatches >= cfg.persistence_required_steps)

        if is_mismatch:
            status = VerificationStatus.VERIFIED_MISMATCH
            reconsideration_recommended = True
            if ceiling_breached:
                explanation = (
                    f"Observed network behavior diverged from model expectation: Security risk ceiling "
                    f"({expectation.risk_ceiling:.2f}) was breached (peak observed risk: {max_risk:.4f}). "
                    "Model assumptions require investigation; reconsideration recommended."
                )
            else:
                explanation = (
                    f"Observed network behavior diverged from model expectation: Persistent feature delta "
                    f"divergence detected across {max_consecutive_mismatches} consecutive observation windows. "
                    "Model assumptions require investigation; reconsideration recommended."
                )
        else:
            status = VerificationStatus.VERIFIED_SUCCESS
            reconsideration_recommended = False
            explanation = (
                "Observed post-action network behavior is consistent with the expected intervention outcome "
                "and configured safety envelope."
            )

        return TrajectoryVerificationResult(
            verification_id=verification_id,
            action_id=action.action_id,
            status=status,
            step_evaluations=step_evals,
            max_observed_risk=max_risk,
            risk_ceiling=expectation.risk_ceiling,
            risk_ceiling_breached=ceiling_breached,
            persistence_count=max_consecutive_mismatches,
            reconsideration_recommended=reconsideration_recommended,
            explanation=explanation,
            evidence_window_ids=tuple(st.window_id for st in eval_states),
        )

    def build_trajectory_reconsideration_handoff(
        self,
        result: TrajectoryVerificationResult,
    ) -> OutcomeMismatchHandoff | None:
        """
        Build an auditable handoff record when trajectory verification detects a mismatch.
        """
        if result.status != VerificationStatus.VERIFIED_MISMATCH:
            return None

        window_id = result.evidence_window_ids[-1] if result.evidence_window_ids else "unknown-window"
        first_step = result.step_evaluations.get(1, {})
        feat_name = str(first_step.get("primary_feature", "trajectory_risk"))
        base_val = float(first_step.get("baseline_value", 0.0))
        obs_val = float(first_step.get("observed_value", 0.0))

        hash_payload = (
            f"{result.action_id}:{feat_name}:{base_val:.4f}:{obs_val:.4f}:{window_id}:{result.persistence_count}"
        )
        prov_hash = sha256(hash_payload.encode("utf-8")).hexdigest()

        return OutcomeMismatchHandoff(
            action_id=result.action_id,
            evidence_window_id=window_id,
            metric_name=feat_name,
            baseline_value=base_val,
            observed_value=obs_val,
            expected_effect=f"Risk <= {result.risk_ceiling:.2f} and conforming feature trajectory",
            observed_effect=f"Peak observed risk: {result.max_observed_risk} (persistence: {result.persistence_count})",
            conflict_summary=result.explanation,
            provenance_hash=prov_hash,
        )


@dataclass(frozen=True)
class TrajectoryVerificationConfig:
    """
    Configurable parameters governing trajectory-based outcome verification.
    All parameters are INITIAL DESIGN PARAMETERS — REQUIRE CALIBRATION.
    """
    base_tolerance: float = 0.10  # INITIAL DESIGN PARAMETER — REQUIRES CALIBRATION
    horizon_expansion_factor: float = 0.25  # kappa in: Tolerance(h) = Base * (1 + kappa * (h - 1)) — REQUIRES CALIBRATION
    min_observation_steps: int = 1
    max_observation_steps: int = 3
    persistence_required_steps: int = 2  # INITIAL DESIGN PARAMETER — REQUIRES CALIBRATION

    def __post_init__(self) -> None:
        if self.base_tolerance <= 0:
            raise ValueError(f"base_tolerance must be positive, got {self.base_tolerance}")
        if self.horizon_expansion_factor < 0:
            raise ValueError(f"horizon_expansion_factor must be non-negative, got {self.horizon_expansion_factor}")
        if self.persistence_required_steps < 1:
            raise ValueError(f"persistence_required_steps must be >= 1, got {self.persistence_required_steps}")


@dataclass(frozen=True)
class TrajectoryOutcomeExpectation:
    """
    Defines operational success and safety bounds for an executed response action
    derived from the Phase 3A intervention-conditioned simulation trajectory.
    """
    action_id: str
    recommended_action: str
    target_entity: str
    baseline_state: NetworkState
    predicted_trajectory: Any
    predicted_risk_trajectory: Any
    risk_ceiling: float  # Inherited directly from Phase 3B DecisionResult.peak_risk_ceiling
    action_ttl_seconds: float = 30.0
    execution_window_id: str = ""
    execution_timestamp_end: datetime = field(default_factory=datetime.now)
    target_features: tuple[str, ...] = ("byte_rate", "packet_rate", "flow_count", "syn_ratio")
    provenance_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.action_id:
            raise ValueError("action_id is required")
        if not self.provenance_hash:
            canonical = (
                f"{self.action_id}:{self.recommended_action}:{self.target_entity}:"
                f"{self.risk_ceiling:.4f}:{self.action_ttl_seconds:.1f}:{self.execution_window_id}"
            )
            object.__setattr__(self, "provenance_hash", sha256(canonical.encode("utf-8")).hexdigest())


@dataclass(frozen=True)
class TrajectoryVerificationResult:
    """
    Immutable audit record of a multi-horizon trajectory verification assessment.
    """
    verification_id: str
    action_id: str
    status: VerificationStatus
    step_evaluations: Mapping[int, Mapping[str, Any]]
    max_observed_risk: float | None
    risk_ceiling: float
    risk_ceiling_breached: bool
    persistence_count: int
    reconsideration_recommended: bool
    explanation: str
    evidence_window_ids: tuple[str, ...] = field(default_factory=tuple)
    provenance_hash: str = field(default="")
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self) -> None:
        if not self.verification_id:
            raise ValueError("verification_id is required")
        if not self.action_id:
            raise ValueError("action_id is required")
        if not self.provenance_hash:
            canonical = (
                f"{self.verification_id}:{self.action_id}:{self.status.value}:"
                f"{self.risk_ceiling:.4f}:{self.risk_ceiling_breached}:{self.persistence_count}"
            )
            object.__setattr__(self, "provenance_hash", sha256(canonical.encode("utf-8")).hexdigest())

    @property
    def is_model_mismatch(self) -> bool:
        return self.status == VerificationStatus.VERIFIED_MISMATCH

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "action_id": self.action_id,
            "status": self.status.value,
            "step_evaluations": {int(k): dict(v) for k, v in self.step_evaluations.items()},
            "max_observed_risk": round(self.max_observed_risk, 4) if self.max_observed_risk is not None else None,
            "risk_ceiling": round(self.risk_ceiling, 4),
            "risk_ceiling_breached": self.risk_ceiling_breached,
            "persistence_count": self.persistence_count,
            "reconsideration_recommended": self.reconsideration_recommended,
            "explanation": self.explanation,
            "evidence_window_ids": list(self.evidence_window_ids),
            "provenance_hash": self.provenance_hash,
            "created_at": self.created_at.isoformat(),
        }
