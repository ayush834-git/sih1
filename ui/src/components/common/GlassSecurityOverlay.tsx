import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useRuntimeStore } from '../../store/useRuntimeStore';
import { GlassPanel } from './GlassPanel';

/**
 * CodeFronts GLZ-15 — Security Event / System Notification Overlay
 *
 * Source: CodeFronts GLZ-15
 * Purpose: Peripheral, non-blocking toast notifications for REAL application events.
 *
 * Real Event Triggers:
 * - TELEMETRY INGESTED (Step advance T0)
 * - HUMAN APPROVAL REQUIRED (Gate pending, routes operator to /pipeline/approve)
 * - ACTION DISPATCHED (Response execution emitted)
 * - MODEL CONTRADICTION / MISMATCH (Verification / Reconsideration divergence)
 *
 * Strict Constraints:
 * - NO fake events or synthetic demo alarms.
 * - Monochrome + #F0C808 palette (no neon / cyberpunk gradients).
 * - Accessible: role="status", aria-live="polite", keyboard dismiss.
 * - Never implies execution has occurred when approval is still pending.
 */

export interface SecurityEventToast {
  id: string;
  type: 'neutral' | 'attention' | 'alert' | 'success';
  title: string;
  detail: string;
  actionRoute?: string;
  actionLabel?: string;
  timestamp: string;
}

export const GlassSecurityOverlay: React.FC = () => {
  const { snapshot } = useRuntimeStore();
  const [toasts, setToasts] = useState<SecurityEventToast[]>([]);
  const navigate = useNavigate();
  const location = useLocation();

  const event = snapshot.event;
  const currentStep = event?.step_index;
  const requiresHuman = event?.requires_human;
  const contradiction = snapshot.reconsideration?.contradictionDetected;

  // Track step progression to emit TELEMETRY INGESTED
  useEffect(() => {
    if (currentStep === undefined) return;

    const timeStr = event?.logical_time_str || new Date().toISOString().slice(11, 19);
    const stepToast: SecurityEventToast = {
      id: `step-${currentStep}-${Date.now()}`,
      type: 'neutral',
      title: `TELEMETRY INGESTED // T0 (STEP ${currentStep})`,
      detail: `Window ${timeStr} · Observed Risk: ${event?.current_risk_score.toFixed(2)}`,
      timestamp: timeStr,
    };

    setToasts((prev) => [...prev.slice(-3), stepToast]);

    // Auto-dismiss neutral after 4.5s
    const timer = setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== stepToast.id));
    }, 4500);

    return () => clearTimeout(timer);
  }, [currentStep]);

  // Track human approval requirement
  useEffect(() => {
    if (!requiresHuman || location.pathname.includes('/pipeline/approve')) {
      setToasts((prev) => prev.filter((t) => !t.id.startsWith('approval-')));
      return;
    }

    const recAction = event?.recommended_actions?.[0]?.action_type || 'CONTAINMENT';
    const approvalToast: SecurityEventToast = {
      id: `approval-${event?.event_id || currentStep}`,
      type: 'attention',
      title: 'APPROVAL REQUIRED // HUMAN GATE',
      detail: `Proposed Action: ${recAction} · Operator evaluation required.`,
      actionRoute: '/pipeline/approve',
      actionLabel: 'REVIEW & AUTHORIZE →',
      timestamp: new Date().toISOString().slice(11, 19),
    };

    setToasts((prev) => {
      if (prev.some((t) => t.id === approvalToast.id)) return prev;
      return [...prev.slice(-2), approvalToast];
    });

    const timer = setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== approvalToast.id));
    }, 12000);

    return () => clearTimeout(timer);
  }, [requiresHuman, currentStep, location.pathname]);

  // Track model mismatch / contradiction
  useEffect(() => {
    if (!contradiction) return;

    const contradictionToast: SecurityEventToast = {
      id: `mismatch-${Date.now()}`,
      type: 'alert',
      title: 'MODEL CONTRADICTION DETECTED',
      detail: snapshot.reconsideration?.reason || 'Empirical telemetry diverges from AR(5) forecast envelope.',
      actionRoute: '/pipeline/verify',
      actionLabel: 'INSPECT VERIFICATION →',
      timestamp: new Date().toISOString().slice(11, 19),
    };

    setToasts((prev) => [...prev.slice(-2), contradictionToast]);

    const timer = setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== contradictionToast.id));
    }, 7000);

    return () => clearTimeout(timer);
  }, [contradiction]);

  const dismissToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  if (toasts.length === 0) return null;

  return (
    <aside
      aria-label="Security system notifications"
      role="status"
      aria-live="polite"
      className="fixed bottom-20 right-6 z-50 max-w-[320px] w-full space-y-2 pointer-events-none"
    >
      {toasts.map((toast) => {
        const isAttention = toast.type === 'attention';
        const isAlert = toast.type === 'alert';

        return (
          <GlassPanel
            key={toast.id}
            variant="default"
            rounded="rounded-2xl"
            className={`pointer-events-auto p-3.5 border transition-all duration-300 shadow-2xl font-mono ${
              isAttention
                ? 'border-[#F0C808]/50 bg-[#0c0c0e]/95 shadow-[0_4px_24px_rgba(240,200,8,0.15)]'
                : isAlert
                ? 'border-red-500/50 bg-[#0e0a0a]/95 shadow-[0_4px_24px_rgba(239,68,68,0.15)]'
                : 'border-white/10 bg-[#08080a]/90'
            }`}
          >
            <div className="flex items-start justify-between gap-2.5">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      isAttention ? 'bg-[#F0C808] animate-ping' : isAlert ? 'bg-red-400 animate-pulse' : 'bg-white/60'
                    }`}
                  />
                  <span
                    className={`text-[10px] tracking-wider uppercase font-bold ${
                      isAttention ? 'text-[#F0C808]' : isAlert ? 'text-red-400' : 'text-[#A1A1AA]'
                    }`}
                  >
                    {toast.title}
                  </span>
                </div>
                <p className="text-xs text-[#71717A] leading-relaxed font-sans">{toast.detail}</p>
              </div>

              <button
                type="button"
                onClick={() => dismissToast(toast.id)}
                aria-label="Dismiss event notification"
                className="text-[#52525B] hover:text-white text-xs p-1 focus:outline-none transition-colors"
              >
                ✕
              </button>
            </div>

            {toast.actionRoute && (
              <button
                type="button"
                onClick={() => {
                  navigate(toast.actionRoute!);
                  dismissToast(toast.id);
                }}
                className={`mt-2.5 w-full py-1.5 px-3 rounded-lg text-[10px] uppercase font-bold tracking-widest transition-all cursor-pointer text-center ${
                  isAttention
                    ? 'bg-[#F0C808] hover:bg-[#FFE14C] text-black shadow-[0_0_10px_rgba(240,200,8,0.25)]'
                    : 'bg-white/10 hover:bg-white/20 text-white'
                }`}
              >
                {toast.actionLabel}
              </button>
            )}
          </GlassPanel>
        );
      })}
    </aside>
  );
};
