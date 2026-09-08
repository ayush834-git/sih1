/**
 * Native Server-Sent Events (SSE) Client for SIH 26153 Predictive Cyber Defense.
 * Connects to /api/v1/stream and streams push-driven runtime events.
 */

import { API_BASE_URL } from './api';
import type {
  DemoEvent,
  DemoStatus,
  ConnectionState,
} from '../types/runtime';

export interface SSEClientCallbacks {
  onState?: (event: DemoEvent) => void;
  onDemoStatus?: (status: DemoStatus) => void;
  onComplete?: (data: { scenario: string; total_steps: number; final_step: number }) => void;
  onError?: (error: { error: string; status?: string } | Error) => void;
  onHeartbeat?: (heartbeat: { ts: string; step: number; status: string }) => void;
  onConnectionChange?: (state: ConnectionState) => void;
}

export class SSEStreamClient {
  private eventSource: EventSource | null = null;
  private callbacks: SSEClientCallbacks;
  private isExplicitlyClosed = false;
  private lastEventId: string | null = null;

  constructor(callbacks: SSEClientCallbacks = {}) {
    this.callbacks = callbacks;
  }

  /**
   * Connect to the SSE endpoint.
   */
  public connect(lastEventId?: string | null): void {
    if (this.eventSource) {
      this.disconnect();
    }

    this.isExplicitlyClosed = false;
    if (lastEventId) {
      this.lastEventId = lastEventId;
    }

    this.callbacks.onConnectionChange?.('CONNECTING');

    const url = new URL(`${API_BASE_URL}/api/v1/stream`);
    if (this.lastEventId !== null && this.lastEventId !== undefined) {
      url.searchParams.set('last_event_id', this.lastEventId);
    }

    try {
      this.eventSource = new EventSource(url.toString());

      this.eventSource.onopen = () => {
        if (!this.isExplicitlyClosed) {
          this.callbacks.onConnectionChange?.('CONNECTED');
        }
      };

      // 1. Live State Event
      this.eventSource.addEventListener('state', (e: MessageEvent) => {
        if (e.lastEventId) {
          this.lastEventId = e.lastEventId;
        }
        try {
          const parsed = JSON.parse(e.data) as DemoEvent;
          this.callbacks.onState?.(parsed);
        } catch (err) {
          console.error('[SSE] Failed to parse state event:', err, e.data);
        }
      });

      // 2. Demo Lifecycle Status Event
      this.eventSource.addEventListener('demo_status', (e: MessageEvent) => {
        try {
          const parsed = JSON.parse(e.data) as DemoStatus;
          this.callbacks.onDemoStatus?.(parsed);
        } catch (err) {
          console.error('[SSE] Failed to parse demo_status event:', err, e.data);
        }
      });

      // 3. Scenario Completed Event
      this.eventSource.addEventListener('complete', (e: MessageEvent) => {
        try {
          const parsed = JSON.parse(e.data);
          this.callbacks.onComplete?.(parsed);
        } catch (err) {
          console.error('[SSE] Failed to parse complete event:', err, e.data);
        }
      });

      // 4. Runtime Error Event
      this.eventSource.addEventListener('error', (e: MessageEvent) => {
        // Distinguish between custom SSE error event with data vs connection error
        if (e.data) {
          try {
            const parsed = JSON.parse(e.data);
            this.callbacks.onError?.(parsed);
            return;
          } catch {
            // fall through
          }
        }
      });

      // 5. Heartbeat Keep-Alive Event
      this.eventSource.addEventListener('heartbeat', (e: MessageEvent) => {
        try {
          const parsed = JSON.parse(e.data);
          this.callbacks.onHeartbeat?.(parsed);
        } catch {
          // ignore heartbeat parse error
        }
      });

      // Global connection error handler (native EventSource auto-reconnects)
      this.eventSource.onerror = () => {
        if (this.isExplicitlyClosed) return;

        if (this.eventSource?.readyState === EventSource.CLOSED) {
          this.callbacks.onConnectionChange?.('DISCONNECTED');
          this.callbacks.onError?.(new Error('SSE connection closed'));
        } else {
          // Native EventSource is reconnecting
          this.callbacks.onConnectionChange?.('CONNECTING');
        }
      };
    } catch (err) {
      this.callbacks.onConnectionChange?.('ERROR');
      this.callbacks.onError?.(err instanceof Error ? err : new Error(String(err)));
    }
  }

  /**
   * Disconnect and release EventSource.
   */
  public disconnect(): void {
    this.isExplicitlyClosed = true;
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    this.callbacks.onConnectionChange?.('DISCONNECTED');
  }

  public getStatus(): { isConnected: boolean; readyState?: number } {
    return {
      isConnected: this.eventSource?.readyState === EventSource.OPEN,
      readyState: this.eventSource?.readyState,
    };
  }
}
