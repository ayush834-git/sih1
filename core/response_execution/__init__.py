"""Response Execution Package (SIH 26153 Task 21).

Provides safe reversible response execution, explicit human approval gating,
and closed-loop outcome verification.

CORE PRINCIPLE:
RECOMMENDATION != AUTHORIZATION != APPROVAL != EXECUTION != VERIFICATION
Destructive actions are PERMANENTLY BLOCKED.
Reversible execution strictly requires explicit human approval.
"""

from core.response_execution.models import (
    ExecutionRecord,
    ExecutionStatus,
    HumanApproval,
    ReversibleActionType,
    ResponseAction,
    RollbackPolicy,
)
from core.response_execution.adapters import DemoResponseAdapter, ResponseAdapter
from core.response_execution.executor import ResponseExecutor
from core.response_execution.verification import (
    OutcomeExpectation,
    OutcomeMismatchHandoff,
    OutcomeVerificationResult,
    OutcomeVerifier,
    TrajectoryOutcomeExpectation,
    TrajectoryVerificationConfig,
    TrajectoryVerificationResult,
    VerificationStatus,
)

__all__ = [
    "ExecutionRecord",
    "ExecutionStatus",
    "HumanApproval",
    "ReversibleActionType",
    "ResponseAction",
    "RollbackPolicy",
    "ResponseAdapter",
    "DemoResponseAdapter",
    "ResponseExecutor",
    "OutcomeExpectation",
    "OutcomeMismatchHandoff",
    "OutcomeVerificationResult",
    "OutcomeVerifier",
    "TrajectoryOutcomeExpectation",
    "TrajectoryVerificationConfig",
    "TrajectoryVerificationResult",
    "VerificationStatus",
]
