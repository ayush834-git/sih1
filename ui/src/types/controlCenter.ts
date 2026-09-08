export type SystemStatusMode = 'NORMAL' | 'DEGRADED' | 'CRITICAL' | 'RECOVERY';

export type UserRole = 'ANALYST_01' | 'OPERATOR_01' | 'THREAT_INTEL' | 'REVIEWER_03' | 'AUDITOR_09' | 'ADMIN_ROOT';

export interface AnalystUser {
  id: string;
  name: string;
  role: UserRole;
  clearance: string;
  title: string;
  avatarUrl?: string;
}

export interface InvestigationCase {
  id: string;
  title: string;
  subject: string;
  threatActor: string;
  attributionConfidence: number;
  status: 'ACTIVE' | 'ESCALATED' | 'CLOSED' | 'PENDING_REVIEW';
  evidenceCount: number;
  supportingCount: number;
  conflictingCount: number;
  sourceReliability: 'HIGH' | 'MEDIUM' | 'LOW';
  hypothesis: string;
  targetVector: string;
  subjectId: string;
  timestamp: string;
  riskType: string;
}

export interface GraphNodeData {
  id: string;
  label: string;
  sublabel: string;
  type: 'SUBJECT' | 'IP' | 'DOMAIN' | 'PGP' | 'CRYPTO' | 'ANOMALY' | 'SECONDARY' | 'SSL' | 'MAIL' | 'ALIAS';
  status?: 'PRIMARY' | 'VERIFIED' | 'UNVERIFIED' | 'SUBDUED';
  confidence?: number;
  x: number;
  y: number;
  isFocused?: boolean;
  degree?: 1 | 2;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  type: 'SOLID' | 'DASHED' | 'ACTIVE' | 'SUBDUED';
  confidence: number;
  label?: string;
}

export type PathTraceStage = 'IDENTITY' | 'PGP' | 'DOMAIN' | 'INFRA';

export interface TimelineMarker {
  id: string;
  date: string;
  label: string;
  type: 'DOMAIN' | 'IP' | 'PGP' | 'TX' | 'ANOMALY' | 'OBSERVATION' | 'CORRELATION' | 'IDENTITY';
  isFocus?: boolean;
  isUncertain?: boolean;
  positionPercent: number;
}

export interface EntityItem {
  id: string;
  name: string;
  type: string;
  observationsCount: number;
  relationshipsCount: number;
  confidence: number;
  lastSeen: string;
  firstObs: string;
  status: 'ACTIVE' | 'FLAGGED' | 'INACTIVE';
  sources: { source: string; count: number; pct: number }[];
  history: { date: string; description: string; source: string; isAccent?: boolean }[];
}

export interface EvidenceRecord {
  id: string;
  caseId: string;
  type: string;
  correlation: string;
  reliability: 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'SUPPORTING' | 'CONFLICTING' | 'UNRESOLVED';
  state: 'VERIFIED' | 'REVIEWED' | 'PENDING';
  source: string;
  collectedAt: string;
  description: string;
  rawObs?: string;
  extracted?: string;
  notes?: string;
  packets?: number;
  volume?: string;
  hops?: number;
  duration?: string;
  supportingSignals?: { id: string; desc: string }[];
  conflictingSignals?: { id: string; type: string; desc: string; confidenceDelta: string }[];
  weights?: { supporting: number; conflicting: number; unresolved: number };
}

export interface AlertRecord {
  id: string;
  caseId: string;
  type: string;
  entity: string;
  confidence: number;
  impact: string;
  explanation: string;
  timestamp: string;
  state: 'OPEN' | 'REVIEW' | 'ACKNOWLEDGED' | 'RESOLVED';
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  observability: 'NORMAL' | 'LIMITED' | 'DEGRADED';
  detectedSignals: string[];
  autonomousAuthority: 'NORMAL' | 'REDUCED' | 'SUSPENDED';
  humanReviewRequired: boolean;
  evidenceTrace: string[];
}

export interface NotificationItem {
  id: string;
  category: 'ALERT' | 'CASE' | 'EVIDENCE' | 'REVIEW' | 'SYSTEM';
  chip: string;
  timeOffset: string;
  title: string;
  description: string;
  isUnread: boolean;
  actionText?: string;
  actionRoute?: string;
  caseId?: string;
  evidenceId?: string;
  isError?: boolean;
}

export interface UserRegistryItem {
  id: string;
  userId: string;
  role: string;
  status: 'ACTIVE' | 'INACTIVE';
  lastActive: string;
}

export interface ActiveSessionItem {
  id: string;
  sessionId: string;
  ipAddress: string;
  device: string;
  location: string;
  lastActive: string;
  isCurrent?: boolean;
}

export interface AuditLogItem {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  object: string;
  result: 'SUCCESS' | 'WARN_DEGRADED' | 'FATAL' | 'DENIED';
  service: string;
  eventCode?: string;
  detail?: string;
  rawHex?: string;
  isError?: boolean;
}

export interface PipelineHealth {
  id: string;
  name: string;
  status: string;
  pct: number;
  isWarning?: boolean;
  detail?: string;
}

export interface SystemDataSource {
  id: string;
  name: string;
  rate: string;
  status: 'ACTIVE' | 'DEGRADED' | 'OFFLINE';
}

export interface ModelMetric {
  name: string;
  version: string;
  drift: string;
  confidence: number;
  isWarning?: boolean;
}
