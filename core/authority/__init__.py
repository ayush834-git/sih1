"""Authority Policy Module (SIH 26153 Task 20).

Translates evidence quality (trust, uncertainty, topology completeness, blast radius)
into explicit operational authority decisions.

CORE PRINCIPLE:
HIGH RISK != HIGH AUTHORITY
Destructive actions are NEVER autonomous.
Missing or invalid evidence inputs fail closed.
"""

from core.authority.models import (
    ActionClass,
    AuthorityDecision,
    AuthorityLevel,
    AuthorityPolicyInput,
)
from core.authority.policy import AuthorityPolicyEngine, POLICY_VERSION

__all__ = [
    "ActionClass",
    "AuthorityDecision",
    "AuthorityLevel",
    "AuthorityPolicyInput",
    "AuthorityPolicyEngine",
    "POLICY_VERSION",
]
