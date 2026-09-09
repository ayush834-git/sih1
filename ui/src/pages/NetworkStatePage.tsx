import React from 'react';
import { useRuntimeStore } from '../store/useRuntimeStore';
import type { DemoEvent, CurrentStateSummary } from '../types/runtime';
import { ConicBorderPanel } from '../components/common/ConicBorderPanel';
import { GlassPanel } from '../components/common/GlassPanel';
import { GlassKpiCountUp } from '../components/common/GlassKpiCountUp';
import { GlassProgressiveDisclosure } from '../components/common/GlassProgressiveDisclosure';

/**
 * Stage 01: OBSERVE — "What is happening right now?"
 * Displays current observed network state, risk, and telemetry evidence.
 * Connected to real backend via useRuntimeStore SSE stream.
 */

// Feature display order for the 15-dimensional state tensor
const FEATURE_LABELS: { key: keyof CurrentStateSummary; label: string; unit: string }[] = [
  { key: 'flow_count', label: 'flow_count', unit: '' },
  { key: 'byte_rate', label: 'byte_rate', unit: 'MB/s' },
  { key: 'packet_rate', label: 'packet_rate', unit: 'pps' },
  { key: 'mean_flow_duration', label: 'mean_flow_duration', unit: 'ms' },
  { key: 'dst_port_diversity', label: 'dst_port_diversity', unit: '' },
  { key: 'syn_ratio', label: 'syn_ratio', unit: '' },
  { key: 'rst_ratio', label: 'rst_ratio', unit: '' },
];

function formatValue(val: number | undefined, unit: string): string {
  if (val === undefined || val === null) return '—';
  if (unit === 'MB/s') return `${(val / 1_000_000).toFixed(1)} MB/s`;
  if (unit === 'pps') return `${val.toLocaleString()} pps`;
  if (unit === 'ms') return `${val.toFixed(0)} ms`;
  if (val > 1000) return val.toLocaleString();
  return val.toFixed(2);
}

function riskToY(risk: number, chartHeight: number = 220, padding: number = 20): number {
  return padding + (1 - risk) * (chartHeight - 2 * padding);
}

function ObservedTrajectoryChart({ events, currentRisk }: { events: DemoEvent[]; currentRisk: number }) {
  const width = 960;
  const height = 220;
  const pad = 20;

  // Use last 4 events for the 30s window (T-30, T-20, T-10, T0)
  const recentEvents = events.slice(-4);
  const points = recentEvents.map((e, i) => {
    const x = pad + 40 + (i / Math.max(recentEvents.length - 1, 1)) * (width - pad - 80);
    const y = riskToY(e.current_risk_score, height, pad);
    return { x, y, risk: e.current_risk_score };
  });

  // If no events, show fallback static
  if (points.length === 0) {
    points.push({ x: width - 40, y: riskToY(currentRisk, height, pad), risk: currentRisk });
  }

  const lastPoint = points[points.length - 1];
  const pathD = points.length > 1
    ? `M ${points.map((p) => `${p.x},${p.y}`).join(' L ')}`
    : '';

  const targetY = riskToY(0.40, height, pad);

  return (
    <GlassPanel variant="default" className="relative w-full h-72 p-6 overflow-hidden select-none border border-[#27272A]/70">
      <svg className="w-full h-full" preserveAspectRatio="none" viewBox={`0 0 ${width} ${height}`}>
        {/* Grid lines */}
        {[0, 0.2, 0.4, 0.6, 0.8, 1.0].map((v) => (
          <line
            key={v}
            x1={60} x2={width - 20}
            y1={riskToY(v, height, pad)} y2={riskToY(v, height, pad)}
            stroke="#181818" strokeWidth={1} opacity={0.4}
          />
        ))}
        {/* Target ceiling line */}
        <line
          x1={60} x2={width - 20}
          y1={targetY} y2={targetY}
          stroke="#F0C808" strokeDasharray="3 3" strokeOpacity={0.6} strokeWidth={1}
        />
        <text x={65} y={targetY - 7} fill="#A1A1AA" fontFamily="'JetBrains Mono', monospace" fontSize={11} fontWeight={500} letterSpacing="0.06em">
          TARGET CEILING 0.40
        </text>

        {/* Area fill */}
        {points.length > 1 && (
          <polygon
            points={`${points.map((p) => `${p.x},${p.y}`).join(' ')} ${lastPoint.x},${height - pad} ${points[0].x},${height - pad}`}
            fill="url(#chartAreaGrad)"
          />
        )}

        {/* Path with animated drawing */}
        {pathD && (
          <path d={pathD} fill="none" stroke="#FFFFFF" strokeWidth={2} className="glz-animate-draw" />
        )}

        {/* Data points */}
        {points.map((p, i) => (
          <circle
            key={i}
            cx={p.x} cy={p.y}
            r={i === points.length - 1 ? 4 : 2.5}
            fill={i === points.length - 1 ? '#F0C808' : '#FFFFFF'}
            stroke={i === points.length - 1 ? '#000001' : 'none'}
            strokeWidth={1.5}
          />
        ))}

        {/* Live T0 pulse dot */}
        <circle
          cx={lastPoint.x}
          cy={lastPoint.y}
          r={7}
          fill="#F0C808"
          opacity={0.35}
          className="glz-live-ping pointer-events-none"
        />

        {/* T0 label */}
        {(() => {
          const pillX = Math.min(Math.max(lastPoint.x, 52), width - 52);
          return (
            <g>
              <rect x={pillX - 43} y={lastPoint.y - 30} width={86} height={24} rx={6} fill="#080808" stroke="#27272A" strokeWidth={1} />
              <text x={pillX} y={lastPoint.y - 14} fill="#F0C808" fontFamily="'JetBrains Mono', monospace" fontSize={11} fontWeight={600} textAnchor="middle">
                T0 : {lastPoint.risk.toFixed(2)}
              </text>
            </g>
          );
        })()}

        <defs>
          <linearGradient id="chartAreaGrad" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#FFFFFF" stopOpacity={0.07} />
            <stop offset="100%" stopColor="#FFFFFF" stopOpacity={0.0} />
          </linearGradient>
        </defs>
      </svg>
      {/* Y-axis labels */}
      <div className="absolute left-3 top-5 bottom-8 flex flex-col justify-between font-mono text-xs text-[#71717A] pointer-events-none">
        {['1.00', '0.80', '0.60', '0.40', '0.20', '0.00'].map((l) => (
          <span key={l}>{l}</span>
        ))}
      </div>
      {/* X-axis labels */}
      <div className="absolute bottom-2 left-16 right-8 flex justify-between font-mono text-xs text-[#71717A] pt-2 border-t border-[#27272A]/40">
        <span>T−30s</span>
        <span>T−20s</span>
        <span>T−10s</span>
        <span className="text-[#F0C808] font-medium">T0 [PRESENT OBSERVED]</span>
      </div>
    </GlassPanel>
  );
}

export const NetworkStatePage: React.FC = () => {
  const { snapshot, eventHistory, connectionState } = useRuntimeStore();

  const event = snapshot.event;
  const state = event?.current_state_summary;
  const riskScore = event?.current_risk_score ?? 0;
  const timeStr = event?.logical_time_str ?? new Date().toISOString().slice(11, 19) + ' UTC';
  const isLive = connectionState === 'CONNECTED';

  // Risk status derivation
  const targetCeiling = 0.40;
  const breach = riskScore - targetCeiling;
  const statusLabel = riskScore > 0.6 ? 'NETWORK ESCALATING' : riskScore > 0.4 ? 'ELEVATED ACTIVITY' : 'NETWORK NOMINAL';

  // Get previous event for delta calculation
  const prevEvent = eventHistory.length >= 2 ? eventHistory[eventHistory.length - 2] : null;
  const prevState = prevEvent?.current_state_summary;

  return (
    <div className="space-y-10">
      {/* TOP SECTION */}
      <section className="space-y-4">
        <div className="font-mono text-xs text-[#71717A] tracking-wider flex items-center gap-2 font-medium">
          <span>OBSERVED NETWORK STATE</span>
          <span className="text-[#27272A]">//</span>
          <span>T0 ({timeStr})</span>
          {!isLive && (
            <span className="text-[#F0C808] ml-2">[DEMO DATA]</span>
          )}
        </div>
        <h1 className="text-5xl font-semibold tracking-tight text-white leading-tight">
          {statusLabel}
        </h1>
        <p className="text-base font-normal text-[#A1A1AA] max-w-2xl leading-relaxed">
          {riskScore > 0.4
            ? 'Observed ingress activity diverging from empirical baseline across current observation window.'
            : 'Network telemetry within established empirical baseline parameters.'}
        </p>
      </section>

      {/* METRIC ANCHORS */}
      <ConicBorderPanel
        as="section"
        variant="live"
        animated={isLive}
        className="p-7 bg-[#080808] rounded-3xl flex flex-col md:flex-row md:items-end justify-between gap-8 shadow-[0_4px_24px_rgba(0,0,0,0.5)]"
      >
        <div className="space-y-2.5">
          <div className="font-mono text-xs uppercase tracking-widest text-[#71717A] font-medium">
            CURRENT OBSERVED RISK
          </div>
          <div className="flex items-baseline gap-3.5 flex-wrap">
            <span className="font-mono text-5xl font-semibold text-white tracking-tight leading-none">
              {riskScore.toFixed(2)}
            </span>
            <span className="font-mono text-base text-[#71717A] font-normal">/ 1.00</span>
            <span className="font-mono text-sm text-[#A1A1AA] pl-3 border-l border-[#27272A]/60">
              Target ceiling {targetCeiling.toFixed(2)}
            </span>
            {breach > 0 && (
              <span className="font-mono text-xs text-[#F0C808] font-bold px-2.5 py-1 rounded-full bg-[#F0C808]/10 border border-[#F0C808]/30">
                +{breach.toFixed(2)} breach
              </span>
            )}
          </div>
        </div>
        <div className="flex flex-wrap sm:flex-nowrap items-center gap-8 md:gap-12 font-mono border-t md:border-t-0 border-[#27272A]/40 pt-4 md:pt-0">
          <div className="space-y-1.5">
            <div className="text-xs text-[#71717A] tracking-wider uppercase font-medium">OBSERVATION WINDOW</div>
            <div className="text-white font-medium text-sm">30-SECOND EMPIRICAL</div>
            <div className="text-xs text-[#A1A1AA] font-normal">T−30s → T0 (Present)</div>
          </div>
          <div className="space-y-1.5">
            <div className="text-xs text-[#71717A] tracking-wider uppercase font-medium">INCIDENT CONTEXT</div>
            <div className="text-white font-medium text-sm">
              {event?.event_id ? `INC-${event.step_index}` : 'INC-PENDING'}
            </div>
            <div className="text-xs text-[#A1A1AA] font-normal">
              {event?.primary_stage ?? 'Awaiting telemetry'}
            </div>
          </div>
        </div>
      </ConicBorderPanel>

      {/* PRIMARY VISUALIZATION */}
      <section className="space-y-3">
        <div className="flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-3">
            <span className="text-[#A1A1AA] uppercase tracking-wider text-sm font-medium">
              EMPIRICAL TRAJECTORY [T-30S → T0]
            </span>
          </div>
          <div className="flex items-center gap-6 text-[#71717A] text-xs">
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 bg-white inline-block rounded-full" />
              <span className="text-[#A1A1AA]">Observed Risk R(t)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 border-b border-dashed border-[#F0C808]/70 inline-block" />
              <span className="text-[#A1A1AA]">Ceiling Target (0.40)</span>
            </div>
          </div>
        </div>
        <ObservedTrajectoryChart events={eventHistory} currentRisk={riskScore} />
      </section>

      {/* TELEMETRY EVIDENCE */}
      <section className="space-y-2.5 font-mono">
        <div className="flex items-center justify-between text-xs text-[#71717A] uppercase tracking-widest font-medium">
          <span>EMPIRICAL TELEMETRY EVIDENCE [T−30s → T0]</span>
        </div>
        <GlassPanel variant="default" className="p-6 grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-[#181818]/70 border border-[#27272A]/60">
          {[
            { label: 'BYTE RATE', key: 'byte_rate' as const, unit: 'MB/s' },
            { label: 'FLOW COUNT', key: 'flow_count' as const, unit: 'flows/s' },
            { label: 'SYN RATIO', key: 'syn_ratio' as const, unit: '' },
          ].map(({ label, key, unit }) => {
            const current = state?.[key];
            const prev = prevState?.[key];
            const delta = current !== undefined && prev !== undefined ? current - prev : undefined;
            return (
              <div key={key} className="flex items-baseline justify-between md:px-6 py-2 md:py-0">
                <span className="text-[#71717A] text-xs tracking-wider font-medium">{label}</span>
                <div className="flex items-baseline gap-2.5">
                  <span className="text-white font-medium text-sm">
                    {current !== undefined ? (
                      key === 'flow_count' ? (
                        <>
                          <GlassKpiCountUp value={current} /> flows/s
                        </>
                      ) : (
                        formatValue(current, unit)
                      )
                    ) : (
                      '—'
                    )}
                  </span>
                  {delta !== undefined && delta !== 0 && (
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                      delta > 0 ? 'bg-[#F0C808]/15 text-[#F0C808]' : 'bg-zinc-800 text-[#A1A1AA]'
                    }`}>
                      {delta > 0 ? '+' : ''}{formatValue(delta, unit)}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </GlassPanel>
      </section>

      {/* PROGRESSIVE DISCLOSURE (CODEFRONTS GLZ-16) */}
      <GlassProgressiveDisclosure
        title="INSPECT FULL 15-DIMENSIONAL NETWORK STATE & INGESTION PROVENANCE"
        badge={`${FEATURE_LABELS.length} FEATURES`}
      >
        <div className="flex items-center justify-between text-[11px] text-[#71717A] border-b border-[#27272A]/50 pb-2">
          <span>TRANSPORT LAYER TELEMETRY ({FEATURE_LABELS.length} FEATURES)</span>
          <span>SAMPLE WINDOW: 30,000ms</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="text-[#71717A] text-[10px] border-b border-[#27272A]/40 uppercase tracking-wider">
                <th className="py-1.5 font-normal">FEATURE IDENTIFIER</th>
                <th className="py-1.5 font-normal">PREVIOUS (T−30s)</th>
                <th className="py-1.5 font-normal">CURRENT (T0)</th>
                <th className="py-1.5 font-normal text-right">OBSERVED DELTA</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#181818] text-[11px]">
              {FEATURE_LABELS.map(({ key, label, unit }) => {
                const curr = state?.[key];
                const prev = prevState?.[key];
                const delta = curr !== undefined && prev !== undefined ? curr - prev : undefined;
                return (
                  <tr key={key}>
                    <td className="py-1.5 text-[#A1A1AA]">{label}</td>
                    <td className="text-[#71717A]">{prev !== undefined ? formatValue(prev, unit) : '—'}</td>
                    <td className="text-white">{curr !== undefined ? formatValue(curr, unit) : '—'}</td>
                    <td className={`text-right ${delta && delta !== 0 ? (Math.abs(delta) > 0.1 ? 'text-[#F0C808]' : 'text-[#A1A1AA]') : 'text-[#71717A]'}`}>
                      {delta !== undefined ? `${delta > 0 ? '+' : ''}${formatValue(delta, unit)}` : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="text-[10px] text-[#71717A] pt-2 border-t border-[#27272A]/40 flex justify-between">
          <span>INGESTION PROVENANCE: SSE STREAM // {connectionState}</span>
          <span>EVENT: {event?.event_id ?? 'PENDING'}</span>
        </div>
      </GlassProgressiveDisclosure>
    </div>
  );
};

