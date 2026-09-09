/**
 * Single Authoritative REST API Client for SIH 26153 Predictive Cyber Defense.
 * Communicates with FastAPI backend runtime endpoints.
 */

import type {
  HealthResponse,
  DemoStatus,
  DemoEvent,
  ForecastCurrentResponse,
  SecurityCurrentResponse,
  DecisionCurrentResponse,
  LiveCaptureStatus,
  ResponseExecutionRequest,
  ResponseExecutionResponse,
  ResponseRollbackRequest,
  ScenarioInfo,
} from '../types/runtime';

export const API_BASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE_URL) || 'http://localhost:8000';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = `HTTP ${res.status}: ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) {
        errorDetail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
      }
    } catch {
      // Use fallback status text
    }
    throw new Error(errorDetail);
  }
  return res.json() as Promise<T>;
}

export const apiClient = {
  /**
   * Health and runtime liveness check.
   */
  async getHealth(): Promise<HealthResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/health`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<HealthResponse>(res);
  },

  /**
   * Get current demo lifecycle status.
   */
  async getDemoStatus(): Promise<DemoStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/demo/status`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<DemoStatus>(res);
  },

  /**
   * Get list of data-backed attack scenarios.
   */
  async getScenarios(): Promise<ScenarioInfo[]> {
    const res = await fetch(`${API_BASE_URL}/api/v1/demo/scenarios`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<ScenarioInfo[]>(res);
  },

  /**
   * Start a simulation scenario.
   */
  async startDemo(scenario = 'scenario_dos_flooding', speed = 1.0): Promise<DemoStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/demo/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ scenario, speed }),
    });
    return handleResponse<DemoStatus>(res);
  },

  /**
   * Pause running simulation.
   */
  async pauseDemo(): Promise<DemoStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/demo/pause`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<DemoStatus>(res);
  },

  /**
   * Resume paused simulation.
   */
  async resumeDemo(): Promise<DemoStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/demo/resume`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<DemoStatus>(res);
  },

  /**
   * Advance simulation by exactly one step.
   */
  async stepDemo(): Promise<DemoStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/demo/step`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<DemoStatus>(res);
  },

  /**
   * Reset simulation back to IDLE.
   */
  async resetDemo(): Promise<DemoStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/demo/reset`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<DemoStatus>(res);
  },

  /**
   * Adjust simulation playback speed multiplier dynamically.
   */
  async setSpeed(speed: number): Promise<DemoStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/demo/speed`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ speed }),
    });
    return handleResponse<DemoStatus>(res);
  },

  /**
   * Get latest calculated DemoEvent.
   */
  async getCurrentState(): Promise<DemoEvent> {
    const res = await fetch(`${API_BASE_URL}/api/v1/state/current`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<DemoEvent>(res);
  },

  /**
   * Get current forecast and feature contributions.
   */
  async getForecast(): Promise<ForecastCurrentResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/forecast/current`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<ForecastCurrentResponse>(res);
  },

  /**
   * Get current security stage, signatures, risk, and explainability.
   */
  async getSecurity(): Promise<SecurityCurrentResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/security/current`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<SecurityCurrentResponse>(res);
  },

  /**
   * Get current decision, priority, and recommended actions.
   */
  async getDecision(): Promise<DecisionCurrentResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/decision/current`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<DecisionCurrentResponse>(res);
  },

  /**
   * Get historical event sequence.
   */
  async getEvents(sinceStep?: number): Promise<DemoEvent[]> {
    const url =
      sinceStep !== undefined
        ? `${API_BASE_URL}/api/v1/events?since_step=${sinceStep}`
        : `${API_BASE_URL}/api/v1/events`;
    const res = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    const data = await handleResponse<{ events?: DemoEvent[] } | DemoEvent[]>(res);
    if (Array.isArray(data)) return data;
    if (Array.isArray((data as { events?: DemoEvent[] })?.events)) {
      return (data as { events: DemoEvent[] }).events;
    }
    return [];
  },

  /**
   * Start genuine live packet capture on Windows loopback interface.
   */
  async startLiveCapture(
    scenario = 'baseline',
    duration_windows = 2,
    speed = 1.0,
    allowed_ports = [8765, 8766, 8767, 8768, 8769, 8770],
  ): Promise<LiveCaptureStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/live/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        scenario,
        duration_windows,
        speed,
        allowed_ports,
      }),
    });
    return handleResponse<LiveCaptureStatus>(res);
  },

  /**
   * Stop live packet capture and persist audit manifest.
   */
  async stopLiveCapture(): Promise<LiveCaptureStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/live/stop`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<LiveCaptureStatus>(res);
  },

  /**
   * Get status of the live packet capture subsystem.
   */
  async getLiveStatus(): Promise<LiveCaptureStatus> {
    const res = await fetch(`${API_BASE_URL}/api/v1/live/status`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<LiveCaptureStatus>(res);
  },

  /**
   * Get the latest live experiment run manifest and provenance audit data.
   */
  async getLiveProvenance(): Promise<Record<string, unknown>> {
    const res = await fetch(`${API_BASE_URL}/api/v1/live/provenance`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<Record<string, unknown>>(res);
  },

  /**
   * Execute an authorized defensive action through the safe ResponseExecutor.
   * Strictly requires human approval and valid authority decision binding.
   */
  async executeResponseAction(req: ResponseExecutionRequest): Promise<ResponseExecutionResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/response/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(req),
    });
    return handleResponse<ResponseExecutionResponse>(res);
  },

  /**
   * Execute a controlled compensating rollback operation (Task 21).
   */
  async rollbackResponseAction(req: ResponseRollbackRequest): Promise<ResponseExecutionResponse> {
    const res = await fetch(`${API_BASE_URL}/api/v1/response/rollback`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(req),
    });
    return handleResponse<ResponseExecutionResponse>(res);
  },

  /**
   * Get history of response execution records for audit.
   */
  async getResponseHistory(): Promise<ResponseExecutionResponse[]> {
    const res = await fetch(`${API_BASE_URL}/api/v1/response/history`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    return handleResponse<ResponseExecutionResponse[]>(res);
  },
};
