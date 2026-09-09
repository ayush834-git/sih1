"""Phase 3: Bounded Simulation & Predictive Defense Decision Layer (SIH 26153).

Phase 3A: Bounded Intervention-Conditioned Forward Simulation
Phase 3B: Disruption Modeling & Minimum-Sufficient Intervention Selection

SIMULATION ONLY: No real execution, no response adapter invocation.
"""
from __future__ import annotations

from simulation.models import (
    AssumptionClassification,
    AssumptionRecord,
    InterventionParameters,
    InterventionStatus,
    InterventionType,
    SimulationResult,
)
from simulation.operator import InterventionOperator
from simulation.engine import InterventionSimulator
from simulation.decision_models import (
    ActionEvaluation,
    DecisionResult,
    DisruptionParameters,
    RecommendationStatus,
    RiskConstraintParameters,
)
from simulation.disruption import DisruptionEstimator
from simulation.selector import MinimumSufficientSelector
from simulation.approval_models import (
    ApprovalConfig,
    ApprovalDecision,
    ApprovalRequest,
    ExecutionGateStatus,
    ExecutionOutcome,
)
from simulation.approval_gate import HumanApprovalGate, INTERVENTION_TO_ACTION_TYPE
from simulation.closed_loop import ClosedLoopCoordinator

__all__ = [
    # Phase 3A
    "AssumptionClassification",
    "AssumptionRecord",
    "InterventionParameters",
    "InterventionStatus",
    "InterventionType",
    "SimulationResult",
    "InterventionOperator",
    "InterventionSimulator",
    # Phase 3B
    "RecommendationStatus",
    "RiskConstraintParameters",
    "DisruptionParameters",
    "ActionEvaluation",
    "DecisionResult",
    "DisruptionEstimator",
    "MinimumSufficientSelector",
    # Phase 3C
    "ExecutionGateStatus",
    "ApprovalConfig",
    "ApprovalRequest",
    "ApprovalDecision",
    "ExecutionOutcome",
    "HumanApprovalGate",
    "INTERVENTION_TO_ACTION_TYPE",
    # Phase 3D
    "ClosedLoopCoordinator",
]
