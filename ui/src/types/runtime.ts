/**
 * Frontend Domain Models for SIH 26153 Predictive Cyber Defense Runtime.
 * Grounded directly in backend contracts (runtime/api.py, scenarios/demo/engine.py, core/contracts.py).
 */

export type DemoLifecycleStatus = 'IDLE' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'ERROR';

export type SecurityStage =
  | 'Unknown'
  | 'Unknown / Benign'
  | 'Reconnaissance'
  | 'Initial Access'
  | 'Execution'
  | 'Persistence'
  | 'Privilege Escalation'
  | 'Defense Evasion'
  | 'Credential Access'
  | 'Discovery'
  | 'Lateral Movement'
  | 'Collection'
  | 'Exfiltration'
  | 'Impact'
  | string;

export type TrustLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'DEGRADED';
export type PriorityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ResponseStrategy = 'MONITOR' | 'INVESTIGATE' | 'CONTAIN' | 'MITIGATE' | 'EVACUATE';
export type UrgencyLevel = 'WHEN_CONVENIENT' | 'PROMPT' | 'IMMEDIATE' | 'CRITICAL';

export type AuthorityLevel =
  | 'OBSERVE'
  | 'ALERT'
  | 'RECOMMEND'
  | 'HUMAN_APPROVAL_REQUIRED'
  | 'BLOCKED';

export type ActionClass =
  | 'OBSERVE_ONLY'
  | 'ALERT_OPERATOR'
  | 'GENERATE_RECOMMENDATION'
  | 'PREPARE_REVERSIBLE_ACTION'
  | 'EXECUTE_REVERSIBLE_ACTION'
  | 'EXECUTE_DESTRUCTIVE_ACTION';

export type ExecutionStatus =
  | 'PROPOSED'
  | 'AWAITING_APPROVAL'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXECUTING'
  | 'EXECUTED'
  | 'VERIFICATION_PENDING'
  | 'VERIFIED_SUCCESS'
  | 'VERIFIED_MISMATCH'
  | 'ROLLBACK_REQUESTED'
  | 'ROLLED_BACK'
  | 'FAILED'
  | 'BLOCKED';

export interface AuthorityDecision {
  decision_id: string;
  authority_level: AuthorityLevel;
  permitted_action_classes: ActionClass[];
  blocked_action_classes: ActionClass[];
  human_approval_required: boolean;
  policy_version: string;
  reason_codes: string[];
  explanation: string;
  provenance_hash: string;
  created_at?: string;
}

export interface HumanApprovalPayload {
  approval_id?: string;
  action_id?: string;
  authority_decision_id?: string;
  evidence_window_id?: string;
  approved: boolean;
  approver_reference: string;
  approval_reason: string;
}

export interface ResponseExecutionRequest {
  action_id?: string;
  action_type: string;
  action_class?: ActionClass;
  target_node_id?: string;
  authority_decision_id?: string;
  evidence_window_id?: string;
  topology_snapshot_id?: string;
  requested_parameters?: Record<string, unknown>;
  expected_effect?: string;
  compensating_action_type?: string;
  approval?: HumanApprovalPayload;
  verification_expectation?: Record<string, unknown>;
  observed_state?: Record<string, unknown>;
}

export interface ResponseRollbackRequest {
  action_id: string;
  target_node_id?: string;
  authority_decision_id?: string;
  compensating_action_type?: string;
  approval?: HumanApprovalPayload;
  reason?: string;
}

export interface ResponseExecutionResponse {
  execution_id: string;
  action_id: string;
  authority_decision_id: string;
  evidence_window_id: string;
  status: ExecutionStatus;
  applied_parameters: Record<string, unknown>;
  approval_id?: string;
  error_message?: string;
  message: string;
  is_verified: boolean;
  verification_status?: string;
  reconsideration_handoff?: Record<string, unknown>;
  is_rollback?: boolean;
}

export interface RecommendedAction {
  action_type: string;
  target: string;
  urgency: UrgencyLevel;
  parameters?: Record<string, unknown>;
  expected_impact?: string;
}

export interface DispatchedNotification {
  notification_id: string;
  recipient_role: string;
  channel: string;
  message: string;
  priority: PriorityLevel;
  dispatched_at: string;
}

export interface LagContribution {
  lag_order: number;
  coefficient: number;
  lag_value: number;
  signed_contribution: number;
  relative_weight: number;
}

export interface ForecastFeatureContribution {
  feature_name: string;
  signed_direction: 'POSITIVE' | 'NEGATIVE' | 'NEUTRAL' | string;
  normalized_contribution: number;
  raw_contribution: number;
  current_value: number;
  predicted_delta: number;
  baseline_reference_value: number;
  evidence_type: 'CURRENT' | 'HISTORICAL' | 'TREND' | string;
  lag_breakdown: LagContribution[];
  description: string;
  is_available: boolean;
}

export interface SecurityExplanation {
  explanation_id: string;
  window_id: string;
  timestamp: string;
  primary_stage: string;
  confidence: number;
  trust_level: string;
  supporting_evidence: string[];
  counter_evidence: string[];
  alternative_explanations: string[];
  top_contributing_features: string[];
  current_vs_forecast_breakdown: Record<string, string>;
  limitations: string[];
  provenance_hash: string;
}

export interface CurrentStateSummary {
  dst_port_diversity: number;
  flow_count: number;
  byte_rate: number;
  syn_ratio: number;
  rst_ratio: number;
  packet_rate?: number;
  mean_flow_duration?: number;
  [key: string]: number | undefined;
}

export interface PredictedDeltasH1 {
  dst_port_diversity_delta: number;
  flow_count_delta: number;
  byte_rate_delta: number;
  packet_rate_delta?: number;
  [key: string]: number | undefined;
}

export interface FutureRiskScores {
  '+10s'?: number;
  '+20s'?: number;
  '+30s'?: number;
  [key: string]: number | undefined;
}

/**
 * Authoritative DemoEvent representing a complete calculated intelligence cycle.
 */
export interface DemoEvent {
  event_id: string;
  step_index: number;
  logical_time_str: string;
  wall_clock_time: string;
  current_state_summary: CurrentStateSummary;
  predicted_deltas_h1: PredictedDeltasH1;
  primary_stage: SecurityStage;
  stage_confidence: number;
  trust_level: TrustLevel;
  composite_trust: number;
  priority_level: PriorityLevel;
  composite_priority: number;
  current_risk_score: number;
  future_risk_scores: FutureRiskScores;
  risk_explanation: string;
  active_signatures: string[];
  candidate_attack_techniques: string[];
  relevant_roles: string[];
  omitted_roles: string[];
  dispatched_notifications: DispatchedNotification[];
  recommended_strategy: ResponseStrategy;
  requires_human: boolean;
  is_reversible: boolean;
  recommended_actions: RecommendedAction[];
  explanation: string;
  forecast_feature_contributions: ForecastFeatureContribution[];
  security_explanation: SecurityExplanation;
  authority_policy?: AuthorityDecision;
  reconsideration?: Record<string, unknown>;
  reconsideration_triggered?: boolean;
  blast_radius?: Record<string, unknown>;
  response_execution?: Record<string, unknown>;
  outcome_verification?: Record<string, unknown>;
}

export type ExecutionMode = 'DEMO' | 'LIVE_PACKET_CAPTURE';

export interface LiveCaptureStatus {
  run_id: string | null;
  is_active: boolean;
  execution_mode: ExecutionMode;
  packets_captured: number;
  in_scope_packets: number;
  out_of_scope_packets: number;
  isolation_violations: string[];
  isolation_passed: boolean;
  states_built: number;
  events_emitted: number;
  generator_running: boolean;
  generator_scenario: string;
}

export interface DemoStatus {
  session_id: string;
  scenario: string;
  status: DemoLifecycleStatus;
  current_step: number;
  total_steps: number;
  history_count: number;
  updated_at: string;
  speed: number;
  execution_mode?: ExecutionMode;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  session_id: string;
  runtime_status: DemoLifecycleStatus;
}

export interface ForecastCurrentResponse {
  step_index: number;
  logical_time_str: string;
  predicted_deltas_h1: PredictedDeltasH1;
  forecast_feature_contributions: ForecastFeatureContribution[];
  provenance_hash: string;
}

export interface SecurityCurrentResponse {
  step_index: number;
  logical_time_str: string;
  primary_stage: SecurityStage;
  stage_confidence: number;
  trust_level: TrustLevel;
  composite_trust: number;
  current_risk_score: number;
  future_risk_scores: FutureRiskScores;
  risk_explanation: string;
  active_signatures: string[];
  candidate_attack_techniques: string[];
  security_explanation: SecurityExplanation;
}

export interface DecisionCurrentResponse {
  step_index: number;
  logical_time_str: string;
  priority_level: PriorityLevel;
  composite_priority: number;
  recommended_strategy: ResponseStrategy;
  requires_human: boolean;
  is_reversible: boolean;
  recommended_actions: RecommendedAction[];
  relevant_roles: string[];
  omitted_roles: string[];
  dispatched_notifications: DispatchedNotification[];
  explanation: string;
}

export type ConnectionState = 'DISCONNECTED' | 'CONNECTING' | 'CONNECTED' | 'ERROR';

/**
 * Derived Reconsideration State tracking shifts in trust, stage, or risk between steps.
 */
export interface ReconsiderationState {
  hasReconsidered: boolean;
  reason: string;
  previousStage: SecurityStage | null;
  currentStage: SecurityStage;
  trustDelta: number;
  riskDelta: number;
  confidenceDelta: number;
  contradictionDetected: boolean;
  timestamp: string;
}

/**
 * Canonical unified RuntimeSnapshot consumed across all UI screens.
 */
export interface RuntimeSnapshot {
  event: DemoEvent | null;
  demo: DemoStatus;
  reconsideration: ReconsiderationState | null;
  lastUpdated: string;
}
