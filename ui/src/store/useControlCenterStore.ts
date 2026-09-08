import { useState, useEffect } from 'react';
import type {
  SystemStatusMode,
  AnalystUser,
  InvestigationCase,
  EntityItem,
  EvidenceRecord,
  AlertRecord,
  AuditLogItem,
  PipelineHealth,
  SystemDataSource,
  ModelMetric,
  NotificationItem,
  UserRegistryItem,
  ActiveSessionItem,
  PathTraceStage,
} from '../types/controlCenter';
import {
  INITIAL_ANALYSTS,
  INITIAL_CASES,
  INITIAL_ENTITIES,
  INITIAL_EVIDENCE,
  INITIAL_ALERTS,
  INITIAL_AUDIT_LOGS,
  INITIAL_PIPELINES,
  INITIAL_DATA_SOURCES,
  INITIAL_MODELS,
  INITIAL_NOTIFICATIONS,
  INITIAL_USER_REGISTRY,
  INITIAL_SESSIONS,
} from '../data/mockData';

interface ControlCenterState {
  systemMode: SystemStatusMode;
  currentUser: AnalystUser;
  activeCaseId: string;
  focusedEntityId: string;
  selectedEvidenceId: string;
  selectedAlertId: string;
  selectedAuditId: string;
  cases: InvestigationCase[];
  entities: EntityItem[];
  evidenceList: EvidenceRecord[];
  alerts: AlertRecord[];
  auditLogs: AuditLogItem[];
  pipelines: PipelineHealth[];
  dataSources: SystemDataSource[];
  models: ModelMetric[];
  notifications: NotificationItem[];
  userRegistry: UserRegistryItem[];
  sessions: ActiveSessionItem[];
  isCommandPaletteOpen: boolean;
  isManualOverrideModalOpen: boolean;
  isNotificationDrawerOpen: boolean;
  isLiveSync: boolean;
  latencyMs: number;
  activeNodesCount: number;
  graphDepth: number;
  selectedFilterChip: string;
  activePathStage: PathTraceStage;
}

let globalState: ControlCenterState = {
  systemMode: 'NORMAL',
  currentUser: INITIAL_ANALYSTS[0],
  activeCaseId: 'CASE-019',
  focusedEntityId: 'ent-1',
  selectedEvidenceId: 'EV-00419',
  selectedAlertId: 'ALERT-0088',
  selectedAuditId: 'AUD-01482',
  cases: INITIAL_CASES,
  entities: INITIAL_ENTITIES,
  evidenceList: INITIAL_EVIDENCE,
  alerts: INITIAL_ALERTS,
  auditLogs: INITIAL_AUDIT_LOGS,
  pipelines: INITIAL_PIPELINES,
  dataSources: INITIAL_DATA_SOURCES,
  models: INITIAL_MODELS,
  notifications: INITIAL_NOTIFICATIONS,
  userRegistry: INITIAL_USER_REGISTRY,
  sessions: INITIAL_SESSIONS,
  isCommandPaletteOpen: false,
  isManualOverrideModalOpen: false,
  isNotificationDrawerOpen: false,
  isLiveSync: true,
  latencyMs: 12,
  activeNodesCount: 4012,
  graphDepth: 2,
  selectedFilterChip: 'ID',
  activePathStage: 'DOMAIN',
};

const listeners = new Set<(state: ControlCenterState) => void>();

function notifyListeners() {
  listeners.forEach((listener) => listener({ ...globalState }));
}

export function useControlCenterStore() {
  const [state, setState] = useState<ControlCenterState>(globalState);

  useEffect(() => {
    const handler = (newState: ControlCenterState) => setState(newState);
    listeners.add(handler);
    return () => {
      listeners.delete(handler);
    };
  }, []);

  const setSystemMode = (mode: SystemStatusMode) => {
    globalState.systemMode = mode;
    const newLog: AuditLogItem = {
      id: `AUD-0${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      actor: globalState.currentUser.name,
      action: 'SYSTEM_STATE_TRANSITION',
      object: `MODE_${mode}`,
      result: mode === 'CRITICAL' ? 'FATAL' : mode === 'DEGRADED' ? 'WARN_DEGRADED' : 'SUCCESS',
      service: 'SYSTEM_ORCHESTRATOR',
      detail: `Operator transitioned system state to ${mode}.`,
    };
    globalState.auditLogs = [newLog, ...globalState.auditLogs];
    notifyListeners();
  };

  const setCurrentUser = (user: AnalystUser) => {
    globalState.currentUser = user;
    notifyListeners();
  };

  const setActiveCaseId = (caseId: string) => {
    globalState.activeCaseId = caseId;
    notifyListeners();
  };

  const setFocusedEntityId = (entityId: string) => {
    globalState.focusedEntityId = entityId;
    notifyListeners();
  };

  const setSelectedEvidenceId = (evidenceId: string) => {
    globalState.selectedEvidenceId = evidenceId;
    notifyListeners();
  };

  const setSelectedAlertId = (alertId: string) => {
    globalState.selectedAlertId = alertId;
    notifyListeners();
  };

  const setSelectedAuditId = (auditId: string) => {
    globalState.selectedAuditId = auditId;
    notifyListeners();
  };

  const setCommandPaletteOpen = (open: boolean) => {
    globalState.isCommandPaletteOpen = open;
    notifyListeners();
  };

  const setManualOverrideModalOpen = (open: boolean) => {
    globalState.isManualOverrideModalOpen = open;
    notifyListeners();
  };

  const setNotificationDrawerOpen = (open: boolean) => {
    globalState.isNotificationDrawerOpen = open;
    notifyListeners();
  };

  const markAllNotificationsRead = () => {
    globalState.notifications = globalState.notifications.map((n) => ({ ...n, isUnread: false }));
    notifyListeners();
  };

  const setGraphDepth = (depth: number) => {
    globalState.graphDepth = depth;
    notifyListeners();
  };

  const setSelectedFilterChip = (chip: string) => {
    globalState.selectedFilterChip = chip;
    notifyListeners();
  };

  const setActivePathStage = (stage: PathTraceStage) => {
    globalState.activePathStage = stage;
    notifyListeners();
  };

  const revokeSession = (sessionId: string) => {
    globalState.sessions = globalState.sessions.filter((s) => s.sessionId !== sessionId);
    const log: AuditLogItem = {
      id: `AUD-0${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      actor: globalState.currentUser.name,
      action: 'SESSION_REVOCATION',
      object: sessionId,
      result: 'SUCCESS',
      service: 'SECURITY_AUTH_PLANE',
      detail: `Revoked active session token for ${sessionId}.`,
    };
    globalState.auditLogs = [log, ...globalState.auditLogs];
    notifyListeners();
  };

  const toggleLiveSync = () => {
    globalState.isLiveSync = !globalState.isLiveSync;
    notifyListeners();
  };

  const isolateSubject = (subjectId: string) => {
    const log: AuditLogItem = {
      id: `AUD-0${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      actor: globalState.currentUser.name,
      action: 'ISOLATE_SUBJECT',
      object: subjectId,
      result: 'SUCCESS',
      service: 'ENDPOINT_ISOLATION_DAEMON',
      detail: `Enforced network containment protocol on subject ${subjectId}.`,
    };
    globalState.auditLogs = [log, ...globalState.auditLogs];
    notifyListeners();
  };

  const escalateCase = (caseId: string) => {
    globalState.cases = globalState.cases.map((c) =>
      c.id === caseId ? { ...c, status: 'ESCALATED' } : c
    );
    const log: AuditLogItem = {
      id: `AUD-0${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      actor: globalState.currentUser.name,
      action: 'CASE_ESCALATION',
      object: caseId,
      result: 'SUCCESS',
      service: 'INCIDENT_RESPONSE_ROUTER',
      detail: `Case ${caseId} escalated to Level-5 Security Operations Director.`,
    };
    globalState.auditLogs = [log, ...globalState.auditLogs];
    notifyListeners();
  };

  const closeCase = (caseId: string) => {
    globalState.cases = globalState.cases.map((c) =>
      c.id === caseId ? { ...c, status: 'CLOSED' } : c
    );
    const log: AuditLogItem = {
      id: `AUD-0${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      actor: globalState.currentUser.name,
      action: 'CASE_RESOLVED',
      object: caseId,
      result: 'SUCCESS',
      service: 'FORENSIC_ARCHIVE',
      detail: `Case ${caseId} closed and archived with signed evidence bundle.`,
    };
    globalState.auditLogs = [log, ...globalState.auditLogs];
    notifyListeners();
  };

  const updateEvidenceReview = (
    evidenceId: string,
    stateType: 'VERIFIED' | 'REVIEWED' | 'PENDING',
    statusType?: 'SUPPORTING' | 'CONFLICTING' | 'UNRESOLVED',
    notes?: string
  ) => {
    globalState.evidenceList = globalState.evidenceList.map((e) => {
      if (e.id === evidenceId) {
        return {
          ...e,
          state: stateType,
          status: statusType || e.status,
          notes: notes !== undefined ? notes : e.notes,
        };
      }
      return e;
    });
    const log: AuditLogItem = {
      id: `AUD-0${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      actor: globalState.currentUser.name,
      action: 'EVIDENCE_ASSESSMENT',
      object: evidenceId,
      result: 'SUCCESS',
      service: 'EVIDENCE_PROVENANCE_HUB',
      detail: `Evidence ${evidenceId} reviewed: marked ${stateType} / ${statusType || 'UNCHANGED'}.`,
    };
    globalState.auditLogs = [log, ...globalState.auditLogs];
    notifyListeners();
  };

  const acknowledgeAlert = (alertId: string) => {
    globalState.alerts = globalState.alerts.map((a) =>
      a.id === alertId ? { ...a, state: 'ACKNOWLEDGED' } : a
    );
    const log: AuditLogItem = {
      id: `AUD-0${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      actor: globalState.currentUser.name,
      action: 'ALERT_ACKNOWLEDGE',
      object: alertId,
      result: 'SUCCESS',
      service: 'ALERT_TRIAGE_LAYER',
      detail: `Alert ${alertId} acknowledged by analyst.`,
    };
    globalState.auditLogs = [log, ...globalState.auditLogs];
    notifyListeners();
  };

  const openInvestigationFromAlert = (alertId: string) => {
    const alert = globalState.alerts.find((a) => a.id === alertId);
    if (alert) {
      globalState.activeCaseId = alert.caseId;
      const log: AuditLogItem = {
        id: `AUD-0${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date().toISOString(),
        actor: globalState.currentUser.name,
        action: 'INVESTIGATION_LAUNCH',
        object: alert.caseId,
        result: 'SUCCESS',
        service: 'CASE_ORCHESTRATOR',
        detail: `Initiated active investigation workspace from alert ${alertId}.`,
      };
      globalState.auditLogs = [log, ...globalState.auditLogs];
    }
    notifyListeners();
  };

  const triggerManualOverride = (justification: string) => {
    globalState.systemMode = 'RECOVERY';
    globalState.isManualOverrideModalOpen = false;
    const log: AuditLogItem = {
      id: `AUD-0${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      actor: globalState.currentUser.name,
      action: 'MANUAL_OVERRIDE_EXECUTED',
      object: 'CORE_CONTROL_PLANE',
      result: 'SUCCESS',
      service: 'CRITICAL_OVERRIDE_GATEWAY',
      detail: `Manual override executed. Justification: "${justification}". Restoring operational baseline.`,
    };
    globalState.auditLogs = [log, ...globalState.auditLogs];
    notifyListeners();
  };

  const activeCase =
    globalState.cases.find((c) => c.id === globalState.activeCaseId) || globalState.cases[0];
  const focusedEntity =
    globalState.entities.find((e) => e.id === globalState.focusedEntityId) || globalState.entities[0];
  const selectedEvidence =
    globalState.evidenceList.find((e) => e.id === globalState.selectedEvidenceId) ||
    globalState.evidenceList[0];
  const selectedAlert =
    globalState.alerts.find((a) => a.id === globalState.selectedAlertId) || globalState.alerts[0];
  const selectedAudit =
    globalState.auditLogs.find((a) => a.id === globalState.selectedAuditId) ||
    globalState.auditLogs[0];

  const unreadNotificationsCount = globalState.notifications.filter((n) => n.isUnread).length;

  return {
    ...state,
    activeCase,
    focusedEntity,
    selectedEvidence,
    selectedAlert,
    selectedAudit,
    unreadNotificationsCount,
    setSystemMode,
    setCurrentUser,
    setActiveCaseId,
    setFocusedEntityId,
    setSelectedEvidenceId,
    setSelectedAlertId,
    setSelectedAuditId,
    setCommandPaletteOpen,
    setManualOverrideModalOpen,
    setNotificationDrawerOpen,
    markAllNotificationsRead,
    setGraphDepth,
    setSelectedFilterChip,
    setActivePathStage,
    revokeSession,
    toggleLiveSync,
    isolateSubject,
    escalateCase,
    closeCase,
    updateEvidenceReview,
    acknowledgeAlert,
    openInvestigationFromAlert,
    triggerManualOverride,
  };
}
