/**
 * Single Canonical Runtime Store for SIH 26153 Predictive Cyber Defense.
 * Synchronizes with FastAPI backend and SSE stream.
 * Provides unified RuntimeSnapshot across all Command Centre pages.
 */

import { useState, useEffect } from 'react';
import { apiClient } from '../lib/api';
import { SSEStreamClient } from '../lib/sse';
import type {
  DemoEvent,
  DemoStatus,
  ConnectionState,
  RuntimeSnapshot,
  ReconsiderationState,
} from '../types/runtime';

export interface RuntimeStoreState {
  snapshot: RuntimeSnapshot;
  eventHistory: DemoEvent[];
  demoStatus: DemoStatus;
  connectionState: ConnectionState;
  error: string | null;
  lastHeartbeat: string | null;
  isInitialized: boolean;
}

const INITIAL_DEMO_STATUS: DemoStatus = {
  session_id: 'sess-init',
  scenario: 'demo_recon_15s',
  status: 'IDLE',
  current_step: -1,
  total_steps: 16,
  history_count: 0,
  updated_at: new Date().toISOString(),
  speed: 1.0,
};

const INITIAL_SNAPSHOT: RuntimeSnapshot = {
  event: null,
  demo: INITIAL_DEMO_STATUS,
  reconsideration: null,
  lastUpdated: new Date().toISOString(),
};

let globalRuntimeState: RuntimeStoreState = {
  snapshot: INITIAL_SNAPSHOT,
  eventHistory: [],
  demoStatus: INITIAL_DEMO_STATUS,
  connectionState: 'DISCONNECTED',
  error: null,
  lastHeartbeat: null,
  isInitialized: false,
};

const listeners = new Set<(state: RuntimeStoreState) => void>();

function notify() {
  listeners.forEach((listener) => listener({ ...globalRuntimeState }));
}

/**
 * Pure derivation function for reconsideration between consecutive telemetry windows.
 */
export function deriveReconsideration(
  prevEvent: DemoEvent | null,
  currEvent: DemoEvent
): ReconsiderationState {
  if (!prevEvent) {
    return {
      hasReconsidered: false,
      reason: 'Baseline telemetry initialized.',
      previousStage: null,
      currentStage: currEvent.primary_stage,
      trustDelta: 0,
      riskDelta: 0,
      confidenceDelta: 0,
      contradictionDetected: false,
      timestamp: currEvent.wall_clock_time,
    };
  }

  const trustDelta = Number((currEvent.composite_trust - prevEvent.composite_trust).toFixed(4));
  const riskDelta = Number((currEvent.current_risk_score - prevEvent.current_risk_score).toFixed(4));
  const confidenceDelta = Number((currEvent.stage_confidence - prevEvent.stage_confidence).toFixed(4));
  const stageChanged = prevEvent.primary_stage !== currEvent.primary_stage;

  const trustDroppedSignificantly = trustDelta <= -0.10;
  const riskElevated = riskDelta >= 0.10;
  const hasCounterEvidence = (currEvent.security_explanation?.counter_evidence?.length ?? 0) > 0;

  let hasReconsidered = false;
  const reasons: string[] = [];

  if (stageChanged) {
    hasReconsidered = true;
    reasons.push(`Security stage transitioned from '${prevEvent.primary_stage}' to '${currEvent.primary_stage}'`);
  }
  if (trustDroppedSignificantly) {
    hasReconsidered = true;
    reasons.push(`Composite trust dropped by ${(Math.abs(trustDelta) * 100).toFixed(1)}%`);
  }
  if (riskElevated) {
    hasReconsidered = true;
    reasons.push(`Security risk increased by ${(riskDelta * 100).toFixed(1)}%`);
  }

  const contradictionDetected = stageChanged || trustDroppedSignificantly || (riskElevated && hasCounterEvidence);

  return {
    hasReconsidered,
    reason: reasons.length > 0 ? reasons.join('; ') : 'Telemetry parameters consistent with current operational model.',
    previousStage: prevEvent.primary_stage,
    currentStage: currEvent.primary_stage,
    trustDelta,
    riskDelta,
    confidenceDelta,
    contradictionDetected,
    timestamp: currEvent.wall_clock_time,
  };
}

let sseClientInstance: SSEStreamClient | null = null;

function getOrCreateSSEClient(): SSEStreamClient {
  if (!sseClientInstance) {
    sseClientInstance = new SSEStreamClient({
      onState: (event: DemoEvent) => {
        // CHAOS 8: Guard against malformed or partial events
        if (!event || typeof event.step_index !== 'number' || isNaN(event.step_index)) {
          console.warn('[RuntimeStore] Dropped invalid or malformed state event:', event);
          return;
        }

        const prevEvent = globalRuntimeState.snapshot.event;
        const currentStep = globalRuntimeState.demoStatus.current_step ?? -1;

        // Deduplicate and maintain monotonic sorted order in event history
        const existingIdx = globalRuntimeState.eventHistory.findIndex(
          (e) => e.step_index === event.step_index || (e.event_id && event.event_id && e.event_id === event.event_id)
        );
        let updatedHistory: DemoEvent[];
        if (existingIdx >= 0) {
          updatedHistory = [...globalRuntimeState.eventHistory];
          updatedHistory[existingIdx] = event;
        } else {
          updatedHistory = [...globalRuntimeState.eventHistory, event];
        }
        updatedHistory.sort((a, b) => a.step_index - b.step_index);

        // CHAOS 2: State must never move backward; latest canonical step remains authoritative
        const isNewerOrEqual = event.step_index >= currentStep;
        const activeEvent = isNewerOrEqual ? event : prevEvent;
        const activeStep = isNewerOrEqual ? event.step_index : currentStep;
        const reconsideration = isNewerOrEqual ? deriveReconsideration(prevEvent, event) : globalRuntimeState.snapshot.reconsideration;

        const updatedDemoStatus: DemoStatus = {
          ...globalRuntimeState.demoStatus,
          current_step: activeStep,
          history_count: updatedHistory.length,
          updated_at: event.wall_clock_time || new Date().toISOString(),
          status: globalRuntimeState.demoStatus.status === 'IDLE' ? 'RUNNING' : globalRuntimeState.demoStatus.status,
        };

        globalRuntimeState = {
          ...globalRuntimeState,
          eventHistory: updatedHistory,
          demoStatus: updatedDemoStatus,
          snapshot: {
            event: activeEvent,
            demo: updatedDemoStatus,
            reconsideration,
            lastUpdated: new Date().toISOString(),
          },
          error: null,
        };
        notify();
      },

      onDemoStatus: (status: DemoStatus) => {
        // CHAOS 6: Clear old session state when transitioning to IDLE
        if (status.status === 'IDLE') {
          globalRuntimeState = {
            ...globalRuntimeState,
            eventHistory: [],
            demoStatus: status,
            snapshot: {
              event: null,
              demo: status,
              reconsideration: null,
              lastUpdated: new Date().toISOString(),
            },
            error: null,
          };
        } else {
          globalRuntimeState = {
            ...globalRuntimeState,
            demoStatus: status,
            snapshot: {
              ...globalRuntimeState.snapshot,
              demo: status,
              lastUpdated: new Date().toISOString(),
            },
          };
        }
        notify();
      },

      onComplete: (data) => {
        const updatedStatus: DemoStatus = {
          ...globalRuntimeState.demoStatus,
          status: 'COMPLETED',
          current_step: data.final_step,
          total_steps: data.total_steps,
          scenario: data.scenario,
          updated_at: new Date().toISOString(),
        };
        globalRuntimeState = {
          ...globalRuntimeState,
          demoStatus: updatedStatus,
          snapshot: {
            ...globalRuntimeState.snapshot,
            demo: updatedStatus,
            lastUpdated: new Date().toISOString(),
          },
        };
        notify();
      },

      onHeartbeat: (hb) => {
        globalRuntimeState = {
          ...globalRuntimeState,
          lastHeartbeat: hb.ts,
        };
        notify();
      },

      onError: (err) => {
        const errorMsg = 'error' in err ? err.error : err.message;
        globalRuntimeState = {
          ...globalRuntimeState,
          error: errorMsg,
        };
        notify();
      },

      onConnectionChange: (connectionState: ConnectionState) => {
        globalRuntimeState = {
          ...globalRuntimeState,
          connectionState,
        };
        notify();
      },
    });
  }
  return sseClientInstance;
}

export function useRuntimeStore() {
  const [state, setState] = useState<RuntimeStoreState>(globalRuntimeState);

  useEffect(() => {
    listeners.add(setState);
    return () => {
      listeners.delete(setState);
    };
  }, []);

  const connectStream = (lastEventId?: string | null) => {
    const client = getOrCreateSSEClient();
    client.connect(lastEventId);
  };

  const disconnectStream = () => {
    if (sseClientInstance) {
      sseClientInstance.disconnect();
    }
  };

  const startDemo = async (scenario = 'demo_recon_15s', speed = 1.0) => {
    try {
      const status = await apiClient.startDemo(scenario, speed);
      globalRuntimeState = {
        ...globalRuntimeState,
        demoStatus: status,
        snapshot: {
          ...globalRuntimeState.snapshot,
          demo: status,
        },
      };
      notify();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      globalRuntimeState = { ...globalRuntimeState, error: msg };
      notify();
      throw err;
    }
  };

  const pauseDemo = async () => {
    try {
      const status = await apiClient.pauseDemo();
      globalRuntimeState = {
        ...globalRuntimeState,
        demoStatus: status,
        snapshot: { ...globalRuntimeState.snapshot, demo: status },
      };
      notify();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      globalRuntimeState = { ...globalRuntimeState, error: msg };
      notify();
      throw err;
    }
  };

  const resumeDemo = async () => {
    try {
      const status = await apiClient.resumeDemo();
      globalRuntimeState = {
        ...globalRuntimeState,
        demoStatus: status,
        snapshot: { ...globalRuntimeState.snapshot, demo: status },
      };
      notify();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      globalRuntimeState = { ...globalRuntimeState, error: msg };
      notify();
      throw err;
    }
  };

  const stepDemo = async () => {
    try {
      await apiClient.stepDemo();
      const status = await apiClient.getDemoStatus();
      globalRuntimeState = {
        ...globalRuntimeState,
        demoStatus: status,
        snapshot: { ...globalRuntimeState.snapshot, demo: status },
      };
      notify();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      globalRuntimeState = { ...globalRuntimeState, error: msg };
      notify();
      throw err;
    }
  };

  const resetDemo = async () => {
    try {
      const status = await apiClient.resetDemo();
      globalRuntimeState = {
        ...globalRuntimeState,
        eventHistory: [],
        demoStatus: status,
        snapshot: {
          event: null,
          demo: status,
          reconsideration: null,
          lastUpdated: new Date().toISOString(),
        },
        error: null,
      };
      notify();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      globalRuntimeState = { ...globalRuntimeState, error: msg };
      notify();
      throw err;
    }
  };

  const setSpeed = async (speed: number) => {
    try {
      const status = await apiClient.setSpeed(speed);
      globalRuntimeState = {
        ...globalRuntimeState,
        demoStatus: status,
        snapshot: { ...globalRuntimeState.snapshot, demo: status },
      };
      notify();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      globalRuntimeState = { ...globalRuntimeState, error: msg };
      notify();
      throw err;
    }
  };

  const initRuntime = async () => {
    if (globalRuntimeState.isInitialized) return;

    try {
      // 1. Fetch current demo status
      const status = await apiClient.getDemoStatus();

      // 2. Fetch current event if one exists
      let currentEvent: DemoEvent | null = null;
      try {
        const fetched = await apiClient.getCurrentState();
        if (fetched && fetched.event_id && fetched.step_index !== undefined && fetched.step_index !== null) {
          currentEvent = fetched;
        }
      } catch {
        // No current event active yet
      }

      // 3. Fetch event history if active
      let history: DemoEvent[] = [];
      try {
        const fetchedHistory = await apiClient.getEvents();
        if (Array.isArray(fetchedHistory)) {
          history = fetchedHistory.filter((e) => e && e.event_id);
        }
      } catch {
        // Optional
      }

      globalRuntimeState = {
        ...globalRuntimeState,
        demoStatus: status,
        eventHistory: history,
        snapshot: {
          event: currentEvent,
          demo: status,
          reconsideration: null,
          lastUpdated: new Date().toISOString(),
        },
        isInitialized: true,
      };
      notify();

      // 4. Connect SSE stream
      connectStream();
    } catch (err) {
      // Backend might still be starting, connect SSE anyway
      globalRuntimeState = {
        ...globalRuntimeState,
        isInitialized: true,
      };
      notify();
      connectStream();
    }
  };

  return {
    ...state,
    startDemo,
    pauseDemo,
    resumeDemo,
    stepDemo,
    resetDemo,
    setSpeed,
    connectStream,
    disconnectStream,
    initRuntime,
  };
}
