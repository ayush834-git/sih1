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
from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import Any, Mapping

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
