"""Intervention Operator for Phase 3A: Bounded Simulation (SIH 26153).

Applies parameter-controlled, deterministic transformations to forecasted future trajectories.

CRITICAL SCIENTIFIC PRINCIPLES:
1. Every transformation is parameterized and explicitly tagged with:
   - "INITIAL DESIGN PARAMETER — REQUIRES CALIBRATION"
   - "UNVALIDATED ASSUMPTION"
2. Transformations only affect features directly supported by the 15-dimensional state.
3. If prerequisites (e.g. source attribution, isolated port) are absent, the operator
   FAILS CLOSED: returns status=UNSUPPORTED with explicit warning records.
4. Input objects are NEVER mutated.
5. NO real network execution is ever performed.
"""
from __future__ import annotations

from typing import Sequence
import numpy as np

from core.contracts import NetworkState
from simulation.models import (
    AssumptionClassification,
    AssumptionRecord,
    InterventionParameters,
    InterventionStatus,
    InterventionType,
)


class InterventionOperator:
    """
    Pure deterministic operator applying hypothetical intervention semantics
    to baseline forecast deltas.
    """

    @staticmethod
    def apply(
        current_state: NetworkState,
        baseline_deltas: np.ndarray,  # Shape: (H, D)
        feature_names: Sequence[str],
        action: InterventionType,
        params: InterventionParameters | None = None,
    ) -> tuple[np.ndarray, tuple[AssumptionRecord, ...], tuple[str, ...], InterventionStatus, float]:
        """
        Apply hypothetical intervention transformation to baseline predicted deltas.

        Returns:
            - intervention_deltas: np.ndarray of shape (H, D)
            - assumptions: tuple of AssumptionRecord
            - warnings: tuple of warning strings
            - status: InterventionStatus (APPLIED, IDENTITY, or UNSUPPORTED)
            - intervention_uncertainty: float representing model uncertainty of the intervention
        """
        if params is None:
            params = InterventionParameters()

        feat_list = list(feature_names)
        H, D = baseline_deltas.shape
        if len(feat_list) != D:
            raise ValueError(f"feature_names length ({len(feat_list)}) must match deltas dimension ({D})")

        # Invariant: Never mutate input baseline_deltas
        intervention_deltas = baseline_deltas.copy()
        assumptions: list[AssumptionRecord] = []
        warnings: list[str] = []

        # ── 1. DO_NOTHING: Exact Identity Mapping ──
        if action == InterventionType.DO_NOTHING:
            return (
                intervention_deltas,
                (),
                (),
                InterventionStatus.IDENTITY,
                0.0,
            )

        # ── 2. RATE_LIMIT_IP: Configurable Volumetric Dampening ──
        elif action == InterventionType.RATE_LIMIT_IP:
            # Features directly supporting traffic rate limitation in 15-D state
            vol_features = ("byte_rate", "packet_rate", "flow_count")
            affected = []
            factor = params.rate_limit_factor

            for vf in vol_features:
                if vf in feat_list:
                    idx = feat_list.index(vf)
                    # Dampen positive growth deltas by configurable factor
                    # Negative deltas (natural decay) are preserved
                    mask_positive = intervention_deltas[:, idx] > 0.0
                    intervention_deltas[mask_positive, idx] *= factor
                    affected.append(vf)

            assumptions.append(
                AssumptionRecord(
                    parameter_name="rate_limit_factor",
                    parameter_value=factor,
                    classification=AssumptionClassification.INITIAL_DESIGN_PARAMETER.value,
                    description=(
                        f"INITIAL DESIGN PARAMETER — REQUIRES CALIBRATION: Hypothetical rate-limiting "
                        f"assumed to scale positive growth deltas of volume features by factor {factor:.2f}. "
                        f"This effect is NOT an empirically measured physical law."
                    ),
                    features_affected=tuple(affected),
                )
            )

            return (
                intervention_deltas,
                tuple(assumptions),
                (),
                InterventionStatus.APPLIED,
                0.20,  # Explicit intervention model uncertainty
            )

        # ── 3. TEMPORARY_BLOCK_IP: Attribution-Gated Source Suppression ──
        elif action == InterventionType.TEMPORARY_BLOCK_IP:
            # Scientific Requirement: DO NOT silently pretend exact source blocking occurred
            # if source attribution is unavailable.
            if not params.source_attribution_valid:
                warning_msg = (
                    "TEMPORARY_BLOCK_IP cannot be simulated defensibly: source IP attribution is "
                    "UNAVAILABLE or unverified in current 15-dimensional state representation. "
                    "Failing closed without modifying trajectory."
                )
                warnings.append(warning_msg)
                return (
                    intervention_deltas,  # Unmodified
                    (),
                    tuple(warnings),
                    InterventionStatus.UNSUPPORTED,
                    1.0,  # Maximum uncertainty due to absent attribution
                )

            # Attribution is valid: apply parameterized volume reduction
            block_features = ("flow_count", "byte_rate", "packet_rate")
            reduction = params.block_volume_reduction
            affected = []

            for bf in block_features:
                if bf in feat_list:
                    idx = feat_list.index(bf)
                    # Assumes attributed source traffic growth is eliminated
                    mask_pos = intervention_deltas[:, idx] > 0.0
                    intervention_deltas[mask_pos, idx] *= (1.0 - reduction)
                    affected.append(bf)

            assumptions.append(
                AssumptionRecord(
                    parameter_name="block_volume_reduction",
                    parameter_value=reduction,
                    classification=AssumptionClassification.UNVALIDATED_ASSUMPTION.value,
                    description=(
                        f"UNVALIDATED ASSUMPTION: Assumes validly attributed source entity traffic is "
                        f"suppressed with reduction ratio {reduction:.2f}. Does not account for adversary "
                        f"evasion, IP rotation, or distributed source infrastructure."
                    ),
                    features_affected=tuple(affected),
                )
            )

            return (
                intervention_deltas,
                tuple(assumptions),
                (),
                InterventionStatus.APPLIED,
                0.35,  # Explicit intervention model uncertainty
            )

        # ── 4. ISOLATE_SERVICE_ENDPOINT: Endpoint Telemetry Gated ──
        elif action == InterventionType.ISOLATE_SERVICE_ENDPOINT:
            # Scientific Requirement: If requested intervention cannot be represented defensibly,
            # record limitation and fail closed.
            if params.isolated_port is None:
                warning_msg = (
                    "ISOLATE_SERVICE_ENDPOINT cannot be simulated defensibly: target port or service "
                    "endpoint is unspecified. 15-dimensional transport telemetry cannot isolate an "
                    "arbitrary endpoint without target port identification. Failing closed."
                )
                warnings.append(warning_msg)
                return (
                    intervention_deltas,  # Unmodified
                    (),
                    tuple(warnings),
                    InterventionStatus.UNSUPPORTED,
                    1.0,
                )

            # Target port is specified: damp destination port exploration
            affected = []
            if "dst_port_diversity" in feat_list:
                port_idx = feat_list.index("dst_port_diversity")
                # Isolating targeted service halts further port scan dispersion on that service
                mask_pos = intervention_deltas[:, port_idx] > 0.0
                intervention_deltas[mask_pos, port_idx] *= 0.50
                affected.append("dst_port_diversity")

            assumptions.append(
                AssumptionRecord(
                    parameter_name="isolated_port",
                    parameter_value=params.isolated_port,
                    classification=AssumptionClassification.UNVALIDATED_ASSUMPTION.value,
                    description=(
                        f"UNVALIDATED ASSUMPTION: Assumes isolation of port {params.isolated_port} "
                        f"suppresses active port exploration growth (dst_port_diversity delta damped by 50%). "
                        f"Observable response depends heavily on adversary reconnaissance methodology."
                    ),
                    features_affected=tuple(affected),
                )
            )

            return (
                intervention_deltas,
                tuple(assumptions),
                (),
                InterventionStatus.APPLIED,
                0.40,  # Explicit intervention model uncertainty
            )

        else:
            raise ValueError(f"Unknown or unsupported intervention action: {action}")
