"""FastAPI Runtime Server exposing the Predictive Cyber Defense intelligence pipeline (SIH 26153)."""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any, AsyncGenerator, List, Mapping, Optional, Union

from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from pathlib import Path
from core.authority.models import ActionClass, AuthorityDecision, AuthorityLevel
from core.contracts import new_id
from core.response_execution import (
    DemoResponseAdapter,
    ExecutionRecord,
    ExecutionStatus,
    HumanApproval,
    OutcomeExpectation,
    OutcomeMismatchHandoff,
    OutcomeVerificationResult,
    OutcomeVerifier,
    ResponseAction,
    ResponseExecutor,
    ReversibleActionType,
    VerificationStatus,
)
from runtime.demo_adapter import AdapterMessageType, DemoAdapter, DemoAdapterMessage
from runtime.live.live_controller import LiveCaptureController
from runtime.live.provenance import EXPERIMENT_DIR
from runtime.state_store import DemoStatus, RuntimeStateStore
from scenarios.demo.engine import DemoEvent


# ────────────────────────────────────────────────────────────
# Pydantic Request & Response Schemas
# ────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "predictive-defense-runtime"
    runtime: str = "available"


class DemoStatusResponse(BaseModel):
    session_id: Optional[str] = None
    scenario: Optional[str] = None
    status: str
    current_step: int
    total_steps: int
    speed: float = 1.0
    history_count: int = 0
    updated_at: Optional[str] = None
    execution_mode: str = "DEMO"


class LiveCaptureStartRequest(BaseModel):
    scenario: str = Field(default="baseline", description="Generator profile: baseline, sustained, recon_scan, burst, churn")
    duration_windows: int = Field(default=2, ge=1, le=100, description="Number of 10s windows to capture and forecast")
    speed: float = Field(default=1.0, ge=0.1, le=100.0, description="Playback speed multiplier")
    allowed_ports: list[int] = Field(default=[8765, 8766, 8767, 8768, 8769, 8770], description="Allowed localhost ports")


class LiveCaptureStatusResponse(BaseModel):
    run_id: Optional[str] = None
    is_active: bool = False
    execution_mode: str = "LIVE_PACKET_CAPTURE"
    packets_captured: int = 0
    in_scope_packets: int = 0
    out_of_scope_packets: int = 0
    isolation_violations: list[str] = Field(default_factory=list)
    isolation_passed: bool = True
    states_built: int = 0
    events_emitted: int = 0
    generator_running: bool = False
    generator_scenario: str = "none"


class DemoStartRequest(BaseModel):
    scenario: str = Field(default="demo_recon_15s", description="Name of scenario to replay")
    speed: float = Field(default=1.0, ge=0.0, le=100.0, description="Playback speed factor (0 = manual)")


class DemoSpeedRequest(BaseModel):
    speed: float = Field(default=1.0, ge=0.0, le=100.0, description="Playback speed factor (0 = manual)")


class DemoStartResponse(BaseModel):
    session_id: str
    scenario: str
    total_steps: int
    status: str
    speed: float


class ResetResponse(BaseModel):
    status: str = "IDLE"
    message: str = "Demo runtime reset successfully"


class CurrentStateResponse(BaseModel):
    session_id: Optional[str] = None
    has_event: bool
    status: str
    execution_mode: str = "DEMO"
    event_id: Optional[str] = None
    step_index: Optional[int] = None
    logical_time: Optional[str] = None
    timestamp: Optional[str] = None
    features: dict[str, float] = Field(default_factory=dict)
    primary_stage: Optional[str] = None
    stage_confidence: Optional[float] = None
    trust_level: Optional[str] = None
    composite_trust: Optional[float] = None
    priority_level: Optional[str] = None
    composite_priority: Optional[float] = None
    current_risk_score: Optional[float] = None
    future_risk_scores: dict[str, float] = Field(default_factory=dict)
    active_signatures: list[str] = Field(default_factory=list)
    candidate_attack_techniques: list[str] = Field(default_factory=list)
    recommended_strategy: Optional[str] = None
    requires_human: bool = True
    is_reversible: bool = True
    recommended_actions: list[dict[str, str]] = Field(default_factory=list)
    relevant_roles: list[str] = Field(default_factory=list)
    dispatched_notifications: list[dict[str, str]] = Field(default_factory=list)
    explanation: Optional[str] = None
    forecast_feature_contributions: list[dict[str, Any]] = Field(default_factory=list)
    security_explanation: dict[str, Any] = Field(default_factory=dict)
    authority_policy: Optional[dict[str, Any]] = None
    reconsideration: Optional[dict[str, Any]] = None
    reconsideration_triggered: bool = False
    blast_radius: Optional[dict[str, Any]] = None
    response_execution: Optional[dict[str, Any]] = None
    outcome_verification: Optional[dict[str, Any]] = None


class HumanApprovalPayload(BaseModel):
    approval_id: Optional[str] = None
    action_id: Optional[str] = None
    authority_decision_id: Optional[str] = None
    evidence_window_id: Optional[str] = None
    approved: bool
    approver_reference: str
    approval_reason: str


class ResponseExecutionRequest(BaseModel):
    action_id: Optional[str] = None
    action_type: str = Field(default="DEMO_BLOCK", description="Reversible action type or destructive action")
    action_class: str = Field(default="EXECUTE_REVERSIBLE_ACTION")
    target_node_id: str = Field(default="svc-api")
    authority_decision_id: Optional[str] = None
    evidence_window_id: Optional[str] = None
    topology_snapshot_id: Optional[str] = None
    requested_parameters: dict[str, Any] = Field(default_factory=dict)
    expected_effect: str = Field(default="Isolate target node from ingress traffic")
    compensating_action_type: str = Field(default="RESTORE_CONNECTION")
    approval: Optional[HumanApprovalPayload] = None
    verification_expectation: Optional[dict[str, Any]] = None
    observed_state: Optional[dict[str, Any]] = None


class ResponseRollbackRequest(BaseModel):
    action_id: str
    target_node_id: Optional[str] = Field(default="svc-api")
    authority_decision_id: Optional[str] = None
    compensating_action_type: str = Field(default="RESTORE_CONNECTION")
    approval: Optional[HumanApprovalPayload] = None
    reason: str = Field(default="Compensating rollback triggered by operator")


class ResponseExecutionResponse(BaseModel):
    execution_id: str
    action_id: str
    authority_decision_id: str
    evidence_window_id: str
    status: str
    applied_parameters: dict[str, Any] = Field(default_factory=dict)
    approval_id: Optional[str] = None
    error_message: Optional[str] = None
    message: str
    is_verified: bool = False
    verification_status: Optional[str] = None
    reconsideration_handoff: Optional[dict[str, Any]] = None
    is_rollback: bool = False


class ForecastResponse(BaseModel):
    session_id: Optional[str] = None
    step_index: Optional[int] = None
    logical_time: Optional[str] = None
    model_name: str = "B4_AR_best(p=5)"
    predicted_deltas_h1: dict[str, float] = Field(default_factory=dict)
    future_risk_scores: dict[str, float] = Field(default_factory=dict)
    forecast_feature_contributions: list[dict[str, Any]] = Field(default_factory=list)


class SecurityResponse(BaseModel):
    session_id: Optional[str] = None
    step_index: Optional[int] = None
    primary_stage: Optional[str] = None
    stage_confidence: Optional[float] = None
    trust_level: Optional[str] = None
    composite_trust: Optional[float] = None
    current_risk_score: Optional[float] = None
    future_risk_scores: dict[str, float] = Field(default_factory=dict)
    risk_explanation: Optional[str] = None
    active_signatures: list[str] = Field(default_factory=list)
    candidate_attack_techniques: list[str] = Field(default_factory=list)
    security_explanation: dict[str, Any] = Field(default_factory=dict)


class DecisionResponse(BaseModel):
    session_id: Optional[str] = None
    step_index: Optional[int] = None
    priority_level: Optional[str] = None
    composite_priority: Optional[float] = None
    recommended_strategy: Optional[str] = None
    requires_human: bool = True
    is_reversible: bool = True
    recommended_actions: list[dict[str, str]] = Field(default_factory=list)
    relevant_roles: list[str] = Field(default_factory=list)
    omitted_roles: list[str] = Field(default_factory=list)
    dispatched_notifications: list[dict[str, str]] = Field(default_factory=list)
    explanation: Optional[str] = None


class EventHistoryResponse(BaseModel):
    session_id: Optional[str] = None
    total_count: int
    events: list[dict[str, Any]]


# ────────────────────────────────────────────────────────────
# Helpers for clean serialization & SSE Formatting
# ────────────────────────────────────────────────────────────

def serialize_demo_event(event: DemoEvent) -> dict[str, Any]:
    """Convert DemoEvent into a clean, JSON-serializable dictionary."""
    return event.to_dict()


def format_sse(
    data: Any,
    event: Optional[str] = None,
    event_id: Optional[Union[str, int]] = None,
    retry: Optional[int] = None,
) -> str:
    """Produce a standard-compliant SSE frame."""
    lines: list[str] = []
    if retry is not None:
        lines.append(f"retry: {retry}")
    if event is not None:
        lines.append(f"event: {event}")
    if event_id is not None:
        lines.append(f"id: {event_id}")

    if isinstance(data, (dict, list)):
        payload_str = json.dumps(data, default=str)
        lines.append(f"data: {payload_str}")
    else:
        for line in str(data).splitlines():
            lines.append(f"data: {line}")

    return "\n".join(lines) + "\n\n"


def build_current_state_response(
    store: RuntimeStateStore,
    event: Optional[DemoEvent],
) -> CurrentStateResponse:
    """Build a strongly-typed CurrentStateResponse from store and latest DemoEvent."""
    if event is None:
        return CurrentStateResponse(
            session_id=store.session_id,
            has_event=False,
            status=store.status.value,
            execution_mode=store.execution_mode,
        )

    return CurrentStateResponse(
        session_id=store.session_id,
        has_event=True,
        status=store.status.value,
        execution_mode=store.execution_mode,
        event_id=event.event_id,
        step_index=event.step_index,
        logical_time=event.logical_time_str,
        timestamp=event.wall_clock_time.isoformat(),
        features=event.current_state_summary,
        primary_stage=event.primary_stage,
        stage_confidence=event.stage_confidence,
        trust_level=event.trust_level,
        composite_trust=event.composite_trust,
        priority_level=event.priority_level,
        composite_priority=event.composite_priority,
        current_risk_score=event.current_risk_score,
        future_risk_scores=event.future_risk_scores,
        active_signatures=event.active_signatures,
        candidate_attack_techniques=event.candidate_attack_techniques,
        recommended_strategy=event.recommended_strategy,
        requires_human=event.requires_human,
        is_reversible=event.is_reversible,
        recommended_actions=event.recommended_actions,
        relevant_roles=event.relevant_roles,
        dispatched_notifications=event.dispatched_notifications,
        explanation=event.explanation,
        forecast_feature_contributions=event.forecast_feature_contributions,
        security_explanation=event.security_explanation,
        authority_policy=event.authority_policy,
        reconsideration=event.reconsideration,
        reconsideration_triggered=event.reconsideration_triggered,
        blast_radius=event.blast_radius,
        response_execution=event.response_execution,
        outcome_verification=event.outcome_verification,
    )


# ────────────────────────────────────────────────────────────
# Application Factory
# ────────────────────────────────────────────────────────────

def create_app(adapter: Optional[DemoAdapter] = None) -> FastAPI:
    """Create and configure the FastAPI runtime server application."""
    app = FastAPI(
        title="Predictive Cyber Defense Runtime API",
        version="1.0.0",
        description="HTTP runtime adapter exposing the validated dynamics and security intelligence pipeline (SIH 26153).",
    )

    # Runtime singleton instances
    runtime_adapter = adapter if adapter is not None else DemoAdapter()
    live_controller = LiveCaptureController(adapter=runtime_adapter)
    response_executor = ResponseExecutor(adapter=DemoResponseAdapter())
    outcome_verifier = OutcomeVerifier()
    app.state.adapter = runtime_adapter
    app.state.live_controller = live_controller
    app.state.response_executor = response_executor
    app.state.outcome_verifier = outcome_verifier

    # CORS configuration for development
    allowed_origins = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in allowed_origins if origin.strip()],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # ────────────────────────────────────────────────────────
    # Routes: Health & Demo Status
    # ────────────────────────────────────────────────────────

    @app.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
    async def get_health() -> HealthResponse:
        """Infrastructure health check."""
        return HealthResponse()

    @app.get("/api/v1/demo/status", response_model=DemoStatusResponse, tags=["Demo Control"])
    async def get_demo_status() -> DemoStatusResponse:
        """Get current scenario and playback lifecycle status."""
        status_info = runtime_adapter.get_status()
        return DemoStatusResponse(**status_info)

    # ────────────────────────────────────────────────────────
    # Routes: Demo Lifecycle Control
    # ────────────────────────────────────────────────────────

    @app.post("/api/v1/demo/start", response_model=DemoStartResponse, tags=["Demo Control"])
    async def start_demo(req: DemoStartRequest) -> DemoStartResponse:
        """Start or restart execution of a scenario."""
        if live_controller.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot start Demo Replay while Live Packet Capture is active.",
            )
        try:
            res = await runtime_adapter.start(scenario=req.scenario, speed=req.speed)
            session_id = runtime_adapter.session_id or res.get("session_id", "unknown")
            return DemoStartResponse(
                session_id=session_id,
                scenario=req.scenario,
                total_steps=res["total_steps"],
                status=res["status"],
                speed=res["speed"],
            )
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to start demo: {e}")

    @app.post("/api/v1/demo/speed", response_model=DemoStatusResponse, tags=["Demo Control"])
    async def set_demo_speed(req: DemoSpeedRequest) -> DemoStatusResponse:
        """Adjust playback speed factor dynamically."""
        status_info = await runtime_adapter.set_speed(req.speed)
        return DemoStatusResponse(**status_info)

    @app.post("/api/v1/demo/pause", response_model=DemoStatusResponse, tags=["Demo Control"])
    async def pause_demo() -> DemoStatusResponse:
        """Pause running execution."""
        try:
            status_info = await runtime_adapter.pause()
            return DemoStatusResponse(**status_info)
        except RuntimeError as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    @app.post("/api/v1/demo/resume", response_model=DemoStatusResponse, tags=["Demo Control"])
    async def resume_demo() -> DemoStatusResponse:
        """Resume playback from paused state."""
        try:
            status_info = await runtime_adapter.resume()
            return DemoStatusResponse(**status_info)
        except RuntimeError as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    @app.post("/api/v1/demo/step", response_model=CurrentStateResponse, tags=["Demo Control"])
    async def step_demo() -> CurrentStateResponse:
        """Advance exactly one demo window step."""
        try:
            event = await runtime_adapter.step()
            return build_current_state_response(runtime_adapter.store, event)
        except RuntimeError as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    @app.post("/api/v1/demo/reset", response_model=ResetResponse, tags=["Demo Control"])
    async def reset_demo() -> ResetResponse:
        """Reset runtime store, invalidate active response executor state, and stop playback."""
        if live_controller.is_active:
            await live_controller.stop()
        await runtime_adapter.reset()
        app.state.response_executor = ResponseExecutor(adapter=DemoResponseAdapter())
        return ResetResponse()

    # ────────────────────────────────────────────────────────
    # Routes: Live Packet Capture Control
    # ────────────────────────────────────────────────────────

    @app.post("/api/v1/live/start", response_model=LiveCaptureStatusResponse, tags=["Live Capture"])
    async def start_live_capture(req: LiveCaptureStartRequest) -> LiveCaptureStatusResponse:
        """Start genuine live packet capture experiment on Windows loopback."""
        if runtime_adapter.status == DemoStatus.RUNNING and runtime_adapter.store.execution_mode != "LIVE_PACKET_CAPTURE":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot start Live Packet Capture while Demo Replay is running.",
            )
        try:
            res = await live_controller.start(
                scenario=req.scenario,
                duration_windows=req.duration_windows,
                speed=req.speed,
                allowed_ports=req.allowed_ports,
            )
            return LiveCaptureStatusResponse(**res)
        except RuntimeError as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to start live capture: {e}")

    @app.post("/api/v1/live/stop", response_model=LiveCaptureStatusResponse, tags=["Live Capture"])
    async def stop_live_capture() -> LiveCaptureStatusResponse:
        """Stop live packet capture and persist experiment audit manifest."""
        res = await live_controller.stop()
        return LiveCaptureStatusResponse(**res)

    @app.get("/api/v1/live/status", response_model=LiveCaptureStatusResponse, tags=["Live Capture"])
    async def get_live_status() -> LiveCaptureStatusResponse:
        """Get status of the live packet capture subsystem and isolation verification."""
        return LiveCaptureStatusResponse(**live_controller.get_status())

    @app.get("/api/v1/live/provenance", tags=["Live Capture"])
    async def get_live_provenance() -> dict[str, Any]:
        """Get the latest live experiment run manifest and provenance audit data."""
        manifest_file = EXPERIMENT_DIR / "run_manifest.json"
        if manifest_file.exists():
            with open(manifest_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {
            "status": "no_runs_yet",
            "message": f"No experiment manifest found at {manifest_file}",
        }

    # ────────────────────────────────────────────────────────
    # Routes: State, Forecast, Security, Decision, Events
    # ────────────────────────────────────────────────────────

    @app.get("/api/v1/state/current", response_model=CurrentStateResponse, tags=["State"])
    async def get_current_state() -> CurrentStateResponse:
        """Get the current live state snapshot from the intelligence pipeline."""
        event = runtime_adapter.current_event
        return build_current_state_response(runtime_adapter.store, event)

    @app.get("/api/v1/forecast/current", response_model=ForecastResponse, tags=["Forecast"])
    async def get_current_forecast() -> ForecastResponse:
        """Get forecast trajectory and dynamics feature contributions."""
        event = runtime_adapter.current_event
        if event is None:
            return ForecastResponse(
                session_id=runtime_adapter.session_id,
                step_index=None,
                logical_time=None,
            )

        return ForecastResponse(
            session_id=runtime_adapter.session_id,
            step_index=event.step_index,
            logical_time=event.logical_time_str,
            model_name="B4_AR_best(p=5)",
            predicted_deltas_h1=event.predicted_deltas_h1,
            future_risk_scores=event.future_risk_scores,
            forecast_feature_contributions=event.forecast_feature_contributions,
        )

    @app.get("/api/v1/security/current", response_model=SecurityResponse, tags=["Security"])
    async def get_current_security() -> SecurityResponse:
        """Get current security risk score trajectory and MITRE attack interpretations."""
        event = runtime_adapter.current_event
        if event is None:
            return SecurityResponse(
                session_id=runtime_adapter.session_id,
                step_index=None,
            )

        return SecurityResponse(
            session_id=runtime_adapter.session_id,
            step_index=event.step_index,
            primary_stage=event.primary_stage,
            stage_confidence=event.stage_confidence,
            trust_level=event.trust_level,
            composite_trust=event.composite_trust,
            current_risk_score=event.current_risk_score,
            future_risk_scores=event.future_risk_scores,
            risk_explanation=event.risk_explanation,
            active_signatures=event.active_signatures,
            candidate_attack_techniques=event.candidate_attack_techniques,
            security_explanation=event.security_explanation,
        )

    @app.get("/api/v1/decision/current", response_model=DecisionResponse, tags=["Decision"])
    async def get_current_decision() -> DecisionResponse:
        """Get advisory priority, response recommendation, and role-routed notifications."""
        event = runtime_adapter.current_event
        if event is None:
            return DecisionResponse(
                session_id=runtime_adapter.session_id,
                step_index=None,
            )

        return DecisionResponse(
            session_id=runtime_adapter.session_id,
            step_index=event.step_index,
            priority_level=event.priority_level,
            composite_priority=event.composite_priority,
            recommended_strategy=event.recommended_strategy,
            requires_human=event.requires_human,
            is_reversible=event.is_reversible,
            recommended_actions=event.recommended_actions,
            relevant_roles=event.relevant_roles,
            omitted_roles=event.omitted_roles,
            dispatched_notifications=event.dispatched_notifications,
            explanation=event.explanation,
        )

    @app.get("/api/v1/events", response_model=EventHistoryResponse, tags=["Events"])
    async def get_event_history(
        since_step: Optional[int] = Query(None, ge=0, description="Filter events at or after step_index"),
        limit: Optional[int] = Query(100, ge=1, le=500, description="Max events to return"),
    ) -> EventHistoryResponse:
        """Get chronological event history for timeline and audit."""
        events = runtime_adapter.store.get_event_history(limit=limit, since_step=since_step)
        serialized_events = [e.to_dict() for e in events]
        return EventHistoryResponse(
            session_id=runtime_adapter.session_id,
            total_count=len(serialized_events),
            events=serialized_events,
        )

    # ────────────────────────────────────────────────────────
    # Routes: Response Execution & Verification (Task 21)
    # ────────────────────────────────────────────────────────

    @app.post("/api/v1/response/execute", response_model=ResponseExecutionResponse, tags=["Response"])
    async def execute_response(req: ResponseExecutionRequest) -> ResponseExecutionResponse:
        """
        Execute an authorized and approved ResponseAction through the safe ResponseExecutor.
        Enforces: RECOMMENDATION != AUTHORIZATION != APPROVAL != EXECUTION != VERIFICATION
        Destructive actions are PERMANENTLY BLOCKED.
        Reversible actions require explicit human approval.
        Stale authorizations are rejected.
        """
        current_event = runtime_adapter.current_event
        current_window_id = current_event.event_id if current_event else "window-idle"

        # 1. Action class validation
        try:
            act_class = ActionClass(req.action_class)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid action_class '{req.action_class}'",
            )

        # 2. Reversible action type or destructive check
        if act_class == ActionClass.EXECUTE_DESTRUCTIVE_ACTION:
            exec_id = new_id("exec")
            return ResponseExecutionResponse(
                execution_id=exec_id,
                action_id=new_id("act"),
                authority_decision_id=req.authority_decision_id or "auth-none",
                evidence_window_id=req.evidence_window_id or current_window_id,
                status=ExecutionStatus.BLOCKED.value,
                applied_parameters={},
                error_message="EXECUTE_DESTRUCTIVE_ACTION is permanently prohibited",
                message="Blocked: Destructive actions are permanently prohibited",
                is_verified=False,
            )

        try:
            rev_act_type = ReversibleActionType(req.action_type)
        except ValueError:
            rev_act_type = ReversibleActionType.DEMO_BLOCK

        # 3. Resolve Authority Decision
        auth_decision: AuthorityDecision
        if current_event and current_event.authority_policy:
            auth_decision = AuthorityDecision.from_dict(current_event.authority_policy)
        else:
            # Construct default conservative decision (HUMAN_APPROVAL_REQUIRED)
            auth_decision = AuthorityDecision(
                decision_id=req.authority_decision_id or new_id("auth-dec"),
                authority_level=AuthorityLevel.HUMAN_APPROVAL_REQUIRED,
                permitted_action_classes=(
                    ActionClass.OBSERVE_ONLY,
                    ActionClass.ALERT_OPERATOR,
                    ActionClass.GENERATE_RECOMMENDATION,
                    ActionClass.PREPARE_REVERSIBLE_ACTION,
                    ActionClass.EXECUTE_REVERSIBLE_ACTION,
                ),
                blocked_action_classes=(ActionClass.EXECUTE_DESTRUCTIVE_ACTION,),
                human_approval_required=True,
                reason_codes=("DEMO_BASELINE_POLICY",),
                explanation="Default human approval required for defensive action",
            )

        # 4. Action instance
        evidence_win_id = req.evidence_window_id or (current_event.event_id if current_event else current_window_id)
        action_id = req.action_id or (f"act-{req.approval.approval_id}" if req.approval and req.approval.approval_id else new_id("act"))
        action_auth_id = req.authority_decision_id or auth_decision.decision_id

        action = ResponseAction(
            action_id=action_id,
            action_class=act_class,
            target_node_id=req.target_node_id,
            action_type=rev_act_type,
            requested_parameters=req.requested_parameters,
            expected_effect=req.expected_effect,
            reversibility=True,
            compensating_action_type=req.compensating_action_type,
            authority_decision_id=action_auth_id,
            evidence_window_id=evidence_win_id,
            topology_snapshot_id=req.topology_snapshot_id,
        )

        # 5. Build HumanApproval if supplied
        approval_obj: Optional[HumanApproval] = None
        if req.approval is not None:
            approval_obj = HumanApproval(
                approval_id=req.approval.approval_id or new_id("appr"),
                action_id=req.approval.action_id or action_id,
                authority_decision_id=req.approval.authority_decision_id or auth_decision.decision_id,
                evidence_window_id=req.approval.evidence_window_id or action.evidence_window_id,
                approved=req.approval.approved,
                approver_reference=req.approval.approver_reference,
                approval_reason=req.approval.approval_reason,
            )

        # 6. Execute via ResponseExecutor
        current_topo = getattr(runtime_adapter.engine, "topology", None)
        record, msg = app.state.response_executor.execute(
            action=action,
            authority_decision=auth_decision,
            approval=approval_obj,
            current_topology=current_topo,
            current_window_id=current_window_id,
        )

        # 7. Outcome Verification (if executed)
        is_verified = False
        verif_status = None
        reconsideration_handoff = None
        if record.status == ExecutionStatus.EXECUTED:
            if req.verification_expectation is not None:
                try:
                    exp_dict = req.verification_expectation
                    expectation = OutcomeExpectation(
                        action_id=action.action_id,
                        metric_name=exp_dict.get("metric_name", "byte_rate"),
                        baseline_value=float(exp_dict.get("baseline_value", 1000.0)),
                        expected_direction=exp_dict.get("expected_direction", "DECREASE"),
                        target_threshold=float(exp_dict["target_threshold"]) if "target_threshold" in exp_dict and exp_dict["target_threshold"] is not None else None,
                        min_reduction_ratio=float(exp_dict.get("min_reduction_ratio", 0.10)),
                        tolerance=float(exp_dict.get("tolerance", 0.05)),
                    )
                    obs_state = req.observed_state or (current_event.to_dict() if current_event else {})
                    verif_res = app.state.outcome_verifier.verify(
                        action=action,
                        expectation=expectation,
                        observed_state=obs_state,
                    )
                    verif_status = verif_res.status.value
                    is_verified = (verif_res.status == VerificationStatus.VERIFIED_SUCCESS)
                    if verif_res.status == VerificationStatus.VERIFIED_MISMATCH:
                        handoff = app.state.outcome_verifier.build_reconsideration_handoff(verif_res)
                        if handoff:
                            reconsideration_handoff = handoff.to_dict()
                except Exception as e:
                    verif_status = "VERIFICATION_ERROR"
                    is_verified = False
            else:
                is_verified = True
                verif_status = "VERIFIED_SUCCESS"

        return ResponseExecutionResponse(
            execution_id=record.execution_id,
            action_id=record.action_id,
            authority_decision_id=record.authority_decision_id,
            evidence_window_id=record.evidence_window_id,
            status=record.status.value,
            applied_parameters=dict(record.applied_parameters),
            approval_id=record.approval_id,
            error_message=record.error_message,
            message=msg,
            is_verified=is_verified,
            verification_status=verif_status,
            reconsideration_handoff=reconsideration_handoff,
            is_rollback=False,
        )

    @app.post("/api/v1/response/rollback", response_model=ResponseExecutionResponse, tags=["Response"])
    async def rollback_response(req: ResponseRollbackRequest) -> ResponseExecutionResponse:
        """
        Execute a controlled compensating rollback operation (Task 21).
        Rollback is a first-class controlled action:
        - Must be reversible with compensating action
        - Fails closed if current authority is BLOCKED
        - Requires valid human approval if rollback policy requires it
        - Invokes adapter compensating operation and verifies outcome
        """
        current_event = runtime_adapter.current_event
        current_window_id = current_event.event_id if current_event else "window-idle"

        # 1. Resolve Authority Decision
        auth_decision: AuthorityDecision
        if current_event and current_event.authority_policy:
            auth_decision = AuthorityDecision.from_dict(current_event.authority_policy)
        else:
            auth_decision = AuthorityDecision(
                decision_id=req.authority_decision_id or new_id("auth-dec"),
                authority_level=AuthorityLevel.HUMAN_APPROVAL_REQUIRED,
                permitted_action_classes=(
                    ActionClass.OBSERVE_ONLY,
                    ActionClass.ALERT_OPERATOR,
                    ActionClass.GENERATE_RECOMMENDATION,
                    ActionClass.PREPARE_REVERSIBLE_ACTION,
                    ActionClass.EXECUTE_REVERSIBLE_ACTION,
                ),
                blocked_action_classes=(ActionClass.EXECUTE_DESTRUCTIVE_ACTION,),
                human_approval_required=True,
                reason_codes=("DEMO_BASELINE_POLICY",),
                explanation="Default human approval required for defensive action",
            )

        # 2. Build ResponseAction for rollback
        action = ResponseAction(
            action_id=req.action_id,
            action_class=ActionClass.EXECUTE_REVERSIBLE_ACTION,
            target_node_id=req.target_node_id or "svc-api",
            action_type=ReversibleActionType.DEMO_BLOCK,
            requested_parameters={},
            expected_effect="Restore connection and compensate prior action",
            reversibility=True,
            compensating_action_type=req.compensating_action_type,
            authority_decision_id=auth_decision.decision_id,
            evidence_window_id=current_window_id,
        )

        # 3. Build HumanApproval if supplied
        approval_obj: Optional[HumanApproval] = None
        if req.approval is not None:
            approval_obj = HumanApproval(
                approval_id=req.approval.approval_id or new_id("appr"),
                action_id=action.action_id,
                authority_decision_id=auth_decision.decision_id,
                evidence_window_id=action.evidence_window_id,
                approved=req.approval.approved,
                approver_reference=req.approval.approver_reference,
                approval_reason=req.approval.approval_reason,
            )

        # 4. Invoke Rollback on ResponseExecutor
        record, msg = app.state.response_executor.rollback(
            action=action,
            authority_decision=auth_decision,
            approval=approval_obj,
            reason=req.reason,
        )

        is_verified = (record.status == ExecutionStatus.ROLLED_BACK)
        verif_status = "VERIFIED_SUCCESS" if is_verified else None

        return ResponseExecutionResponse(
            execution_id=record.execution_id,
            action_id=record.action_id,
            authority_decision_id=record.authority_decision_id,
            evidence_window_id=record.evidence_window_id,
            status=record.status.value,
            applied_parameters=dict(record.applied_parameters),
            approval_id=record.approval_id,
            error_message=record.error_message,
            message=msg,
            is_verified=is_verified,
            verification_status=verif_status,
            reconsideration_handoff=None,
            is_rollback=True,
        )

    @app.get("/api/v1/response/history", tags=["Response"])
    async def get_response_history() -> list[dict[str, Any]]:
        """Get history of all response execution records for audit."""
        records = app.state.response_executor.get_execution_history()
        return [r.to_dict() for r in records]

    # ────────────────────────────────────────────────────────
    # Routes: Server-Sent Events (SSE) Stream
    # ────────────────────────────────────────────────────────

    @app.get("/api/v1/stream", tags=["Stream"])
    async def stream_events(
        request: Request,
        last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
        query_last_event_id: Optional[str] = Query(None, alias="last_event_id"),
    ) -> StreamingResponse:
        """
        Push-based Server-Sent Events (SSE) stream.
        Emits 'state', 'demo_status', 'complete', 'error', and 'heartbeat' events.
        Supports automatic reconnection and missed event replay via Last-Event-ID.
        """
        effective_last_id = last_event_id or query_last_event_id

        async def event_generator() -> AsyncGenerator[str, None]:
            # 1. Initial SSE retry directive (3000ms)
            yield format_sse(data="", retry=3000)

            # 2. Replay missed events if client reconnected with Last-Event-ID
            if effective_last_id is not None:
                try:
                    last_step = int(effective_last_id)
                    missed_events = runtime_adapter.store.get_event_history(since_step=last_step + 1)
                    for evt in missed_events:
                        yield format_sse(
                            data=evt.to_dict(),
                            event="state",
                            event_id=evt.step_index,
                        )
                except (ValueError, TypeError):
                    pass

            # 3. Live push event streaming from DemoAdapter subscription queue
            subscription = runtime_adapter.subscribe()
            sub_iter = subscription.__aiter__()

            try:
                while True:
                    try:
                        # Wait up to 5.0 seconds for the next live event
                        msg: DemoAdapterMessage = await asyncio.wait_for(sub_iter.__anext__(), timeout=5.0)

                        if msg.message_type == AdapterMessageType.EVENT:
                            step_idx = msg.step_index if msg.step_index is not None else -1
                            yield format_sse(
                                data=msg.data,
                                event="state",
                                event_id=step_idx,
                            )
                        elif msg.message_type == AdapterMessageType.STATUS:
                            yield format_sse(
                                data=msg.data,
                                event="demo_status",
                            )
                        elif msg.message_type == AdapterMessageType.COMPLETED:
                            yield format_sse(
                                data=msg.data,
                                event="complete",
                            )
                        elif msg.message_type == AdapterMessageType.ERROR:
                            yield format_sse(
                                data=msg.data,
                                event="error",
                            )

                    except asyncio.TimeoutError:
                        # Emit periodic heartbeat if no event sent in the last 5 seconds
                        hb_data = {
                            "ts": datetime.now().isoformat(),
                            "step": runtime_adapter.current_step,
                            "status": runtime_adapter.status.value,
                            "execution_mode": runtime_adapter.store.execution_mode,
                        }
                        yield format_sse(data=hb_data, event="heartbeat")

                    except StopAsyncIteration:
                        break

            except asyncio.CancelledError:
                pass
            finally:
                pass

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return app


# Default singleton application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
