"""Data contracts for Phase 3A: Bounded Intervention-Conditioned Simulation (SIH 26153).

Provides explicit, immutable data models representing:
- Hypothetical intervention actions
- Configurable intervention parameters with explicit assumption classifications
- Intermediate comparative simulation results
- Explicit separation of forecast uncertainty and intervention model uncertainty

CRITICAL SCIENTIFIC INVARIANT:
Intervention simulation is NOT causal inference or counterfactual reasoning.
Terminology:
- intervention-conditioned forward simulation
- model-based what-if trajectory
- hypothetical mitigation roll-forward
- comparative trajectory evaluation
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import Any, Mapping

from core.contracts import Trajectory
from security.contracts import SecurityRiskTrajectory


class InterventionType(str, Enum):
    """
    Admissible intervention actions for Phase 3A bounded simulation.
    Only these four actions are permitted.
    """
    DO_NOTHING = "DO_NOTHING"
    RATE_LIMIT_IP = "RATE_LIMIT_IP"
    TEMPORARY_BLOCK_IP = "TEMPORARY_BLOCK_IP"
    ISOLATE_SERVICE_ENDPOINT = "ISOLATE_SERVICE_ENDPOINT"


class InterventionStatus(str, Enum):
    """Execution status of the hypothetical intervention transformation."""
    APPLIED = "APPLIED"          # Parameterized transformation applied to future lookahead.
    IDENTITY = "IDENTITY"        # Identity transformation reproducing baseline (e.g. DO_NOTHING).
    UNSUPPORTED = "UNSUPPORTED"  # Transformation cannot be defensibly represented; failed closed.


class AssumptionClassification(str, Enum):
    """
    Explicit classification of engineering assumptions.
    Every intervention parameter must be tagged with one of these.
    DO NOT represent these parameters as measured empirical facts.
    """
    INITIAL_DESIGN_PARAMETER = "INITIAL DESIGN PARAMETER — REQUIRES CALIBRATION"
    UNVALIDATED_ASSUMPTION = "UNVALIDATED ASSUMPTION"


@dataclass(frozen=True)
class AssumptionRecord:
    """An explicit, inspectable assumption statement attached to a simulated transformation."""
    parameter_name: str
    parameter_value: Any
    classification: str
    description: str
    features_affected: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "parameter_name": self.parameter_name,
            "parameter_value": self.parameter_value,
            "classification": self.classification,
            "description": self.description,
            "features_affected": list(self.features_affected),
        }


@dataclass(frozen=True)
class InterventionParameters:
    """
    Configurable parameters governing the hypothetical intervention operator.
    All parameters have explicit defaults and must be treated as design parameters
    requiring empirical calibration rather than established physical laws.
    """
    rate_limit_factor: float = 0.50  # INITIAL DESIGN PARAMETER — REQUIRES CALIBRATION
    block_volume_reduction: float = 1.0  # UNVALIDATED ASSUMPTION — assumes full source removal
    source_attribution_valid: bool = False  # Prerequisite for TEMPORARY_BLOCK_IP
    isolated_port: int | None = None  # Prerequisite for ISOLATE_SERVICE_ENDPOINT
    target_entity: str = ""  # IP or endpoint descriptor
    extra_parameters: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (0.0 <= self.rate_limit_factor <= 1.0):
            raise ValueError(f"rate_limit_factor must be in [0, 1], got {self.rate_limit_factor}")
        if not (0.0 <= self.block_volume_reduction <= 1.0):
            raise ValueError(f"block_volume_reduction must be in [0, 1], got {self.block_volume_reduction}")
        if self.isolated_port is not None and not (1 <= self.isolated_port <= 65535):
            raise ValueError(f"isolated_port must be in [1, 65535], got {self.isolated_port}")


@dataclass(frozen=True)
class SimulationResult:
    """
    Deterministic comparative evaluation between a baseline AR(5) forecast trajectory
    and an intervention-conditioned what-if trajectory.

    Exposes future risk trajectories, risk deltas, peak risks, explicit assumptions,
    and warnings without prematurely coupling to Phase 4 decision policies.
    """
    action: InterventionType
    status: InterventionStatus
    baseline_trajectory: Trajectory
    intervention_trajectory: Trajectory
    baseline_risk: SecurityRiskTrajectory
    intervention_risk: SecurityRiskTrajectory
    risk_delta: float  # intervention peak risk - baseline peak risk (negative implies risk reduction)
    risk_reduction: float  # max(0.0, baseline peak risk - intervention peak risk)
    peak_baseline_risk: float
    peak_intervention_risk: float
    horizon_risk_deltas: Mapping[int, float]  # h -> (intervention_risk(t+h) - baseline_risk(t+h))
    assumptions: tuple[AssumptionRecord, ...]
    warnings: tuple[str, ...]
    forecast_uncertainty: Mapping[int, float]  # Preserves existing AR(5) / horizon uncertainty
    intervention_uncertainty: float  # Explicit uncertainty of the intervention transformation
    provenance_hash: str
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "status": self.status.value,
            "baseline_trajectory_id": self.baseline_trajectory.trajectory_id,
            "intervention_trajectory_id": self.intervention_trajectory.trajectory_id,
            "baseline_risk": self.baseline_risk.to_dict(),
            "intervention_risk": self.intervention_risk.to_dict(),
            "risk_delta": round(self.risk_delta, 4),
            "risk_reduction": round(self.risk_reduction, 4),
            "peak_baseline_risk": round(self.peak_baseline_risk, 4),
            "peak_intervention_risk": round(self.peak_intervention_risk, 4),
            "horizon_risk_deltas": {str(h): round(v, 4) for h, v in self.horizon_risk_deltas.items()},
            "assumptions": [a.to_dict() for a in self.assumptions],
            "warnings": list(self.warnings),
            "forecast_uncertainty": {str(h): round(v, 4) for h, v in self.forecast_uncertainty.items()},
            "intervention_uncertainty": round(self.intervention_uncertainty, 4),
            "provenance_hash": self.provenance_hash,
            "created_at": self.created_at.isoformat(),
        }
