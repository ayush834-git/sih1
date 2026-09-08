"""Role Taxonomy and Profiles for Operational Routing (SIH 26153)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from core.contracts import PriorityLevel, Role
from security.contracts import SignatureType


class OperationalRole(str, Enum):
    SOC_ANALYST = "SOC_ANALYST"
    NETWORK_DEFENDER = "NETWORK_DEFENDER"
    INCIDENT_COMMANDER = "INCIDENT_COMMANDER"
    DATA_PROTECTION = "DATA_PROTECTION"
    ENDPOINT_ANALYST = "ENDPOINT_ANALYST"

    def to_contract_role(self) -> Role:
        """Map operational role to frozen contract Role enum."""
        mapping = {
            OperationalRole.SOC_ANALYST: Role.INCIDENT_RESPONSE,
            OperationalRole.NETWORK_DEFENDER: Role.NETWORK_SECURITY,
            OperationalRole.INCIDENT_COMMANDER: Role.INCIDENT_RESPONSE,
            OperationalRole.DATA_PROTECTION: Role.CLOUD_SYSTEM_ADMIN,
            OperationalRole.ENDPOINT_ANALYST: Role.INCIDENT_RESPONSE,
        }
        return mapping[self]


@dataclass(frozen=True)
class RoleProfile:
    """Configurable operational profile defining relevant signatures, stages, and priorities."""
    role: OperationalRole
    display_name: str
    relevant_signatures: tuple[SignatureType, ...]
    relevant_stages: tuple[str, ...]
    min_priority: PriorityLevel
    response_domains: tuple[str, ...]


DEFAULT_ROLE_PROFILES: dict[OperationalRole, RoleProfile] = {
    OperationalRole.SOC_ANALYST: RoleProfile(
        role=OperationalRole.SOC_ANALYST,
        display_name="SOC Triage Analyst",
        relevant_signatures=(
            SignatureType.RECONNAISSANCE_PORT_EXPLORATION,
            SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE,
            SignatureType.EXFILTRATION_OUTBOUND_SURGE,
            SignatureType.TIMING_BEHAVIOURAL_ANOMALY,
        ),
        relevant_stages=(
            "Reconnaissance",
            "Initial Access / Delivery",
            "Impact / Denial of Service",
            "Collection / Exfiltration",
        ),
        min_priority=PriorityLevel.LOW,
        response_domains=("Triage Queue", "Telemetry Collection", "Inspection"),
    ),
    OperationalRole.NETWORK_DEFENDER: RoleProfile(
        role=OperationalRole.NETWORK_DEFENDER,
        display_name="Network Infrastructure Defender",
        relevant_signatures=(
            SignatureType.RECONNAISSANCE_PORT_EXPLORATION,
            SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE,
            SignatureType.EXFILTRATION_OUTBOUND_SURGE,
        ),
        relevant_stages=(
            "Reconnaissance",
            "Impact / Denial of Service",
            "Collection / Exfiltration",
        ),
        min_priority=PriorityLevel.LOW,
        response_domains=("Firewall ACLs", "Rate Limiting", "Traffic Shaping", "Boundary Protection"),
    ),
    OperationalRole.INCIDENT_COMMANDER: RoleProfile(
        role=OperationalRole.INCIDENT_COMMANDER,
        display_name="Incident Response Commander",
        relevant_signatures=(
            SignatureType.CONNECTION_FLOODING_RESOURCE_PRESSURE,
            SignatureType.EXFILTRATION_OUTBOUND_SURGE,
            SignatureType.RECONNAISSANCE_PORT_EXPLORATION,
        ),
        relevant_stages=(
            "Impact / Denial of Service",
            "Collection / Exfiltration",
            "Reconnaissance",
        ),
        min_priority=PriorityLevel.HIGH,  # Commander only alerted on HIGH / CRITICAL or confirmed multi-step trends
        response_domains=("Incident Escalation", "Operational Coordination", "Executive Reporting"),
    ),
    OperationalRole.DATA_PROTECTION: RoleProfile(
        role=OperationalRole.DATA_PROTECTION,
        display_name="Data Protection & Privacy Officer",
        relevant_signatures=(
            SignatureType.EXFILTRATION_OUTBOUND_SURGE,
        ),
        relevant_stages=(
            "Collection / Exfiltration",
        ),
        min_priority=PriorityLevel.MEDIUM,
        response_domains=("Data Loss Prevention", "Regulatory Compliance", "Asset Audit"),
    ),
    OperationalRole.ENDPOINT_ANALYST: RoleProfile(
        role=OperationalRole.ENDPOINT_ANALYST,
        display_name="Host & Endpoint Security Analyst",
        relevant_signatures=(
            SignatureType.LATERAL_FAN_OUT,  # Requires endpoint topology
        ),
        relevant_stages=(
            "Lateral Movement",
        ),
        min_priority=PriorityLevel.MEDIUM,
        response_domains=("Host Isolation", "EDR Process Tree", "Credential Audit"),
    ),
}
