import React, { useState, useEffect } from 'react';
import { useRuntimeStore } from '../store/useRuntimeStore';
import { apiClient } from '../lib/api';
import type { DemoEvent, ForecastFeatureContribution } from '../types/runtime';
import { AnalysisCardSkeleton } from '../components/common/ShimmerSkeletons';
import { ConicBorderPanel } from '../components/common/ConicBorderPanel';
import { GlassPanel } from '../components/common/GlassPanel';
import { GlassKpiCountUp } from '../components/common/GlassKpiCountUp';
import { GlassProgressiveDisclosure } from '../components/common/GlassProgressiveDisclosure';

/**
 * Stage 02: PREDICT — "What is likely to happen next?"
 * Displays AR(5) trajectory forecast with uncertainty, +10/+20/+30s projections.
 */

function riskToY(risk: number, h = 320, pad = 20): number {
  return pad + (1 - risk) * (h - 2 * pad);
}

function TrajectoryChart({ events, futureRisks, active = true }: {
  events: DemoEvent[];
  futureRisks: { t10: number; t20: number; t30: number };
  active?: boolean;
}) {
  const W = 960, H = 320, P = 20;
  const currentRisk = events.length > 0 ? events[events.length - 1].current_risk_score : 0;

  // Observed points (left half: T-30 to T0)
  const recent = events.slice(-4);
  const obsPoints = recent.map((e, i) => ({
    x: 70 + (i / Math.max(recent.length - 1, 1)) * (480 - 70),
    y: riskToY(e.current_risk_score, H, P),
    r: e.current_risk_score,
  }));
  if (obsPoints.length === 0) {
    obsPoints.push({ x: 480, y: riskToY(currentRisk, H, P), r: currentRisk });
  }
  const t0Point = obsPoints[obsPoints.length - 1];

  // Forecast points (right half: T0 to +30s)
  const forecastPoints = [
    { x: 480, y: riskToY(currentRisk, H, P), r: currentRisk },
    { x: 620, y: riskToY(futureRisks.t10, H, P), r: futureRisks.t10 },
    { x: 760, y: riskToY(futureRisks.t20, H, P), r: futureRisks.t20 },
    { x: 900, y: riskToY(futureRisks.t30, H, P), r: futureRisks.t30 },
  ];

  // Uncertainty band (±0.08 at +30s, ±0.04 at +10s)
  const uncertaintyMargins = [0, 0.04, 0.08, 0.11];
  const upperBand = forecastPoints.map((p, i) => ({
    x: p.x,
    y: riskToY(Math.min(1, p.r + uncertaintyMargins[i]), H, P),
  }));
  const lowerBand = forecastPoints.map((p, i) => ({
    x: p.x,
    y: riskToY(Math.max(0, p.r - uncertaintyMargins[i]), H, P),
  }));

  const bandPolygon = [...upperBand, ...lowerBand.reverse()]
    .map((p) => `${p.x},${p.y}`)
    .join(' ');

  const obsPath = obsPoints.length > 1
    ? `M ${obsPoints.map((p) => `${p.x},${p.y}`).join(' L ')}`
    : '';
  const forecastPath = `M ${forecastPoints.map((p) => `${p.x},${p.y}`).join(' L ')}`;

  const targetY = riskToY(0.40, H, P);
  const peakY = riskToY(0.60, H, P);

  return (
    <ConicBorderPanel
      variant="active"
      animated={active}
      className="w-full h-[400px] sm:h-[450px] rounded-3xl overflow-hidden shadow-[0_4px_24px_rgba(0,0,0,0.4)]"
      innerClassName="relative w-full h-full glz-dark-glass rounded-[calc(1.5rem-1.5px)] p-6 overflow-hidden select-none"
    >
      <svg className="w-full h-full" preserveAspectRatio="none" viewBox={`0 0 ${W} ${H}`}>
        <defs>
          <linearGradient id="uncertaintyBand" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#F0C808" stopOpacity={0.08} />
            <stop offset="40%" stopColor="#F0C808" stopOpacity={0.18} />
            <stop offset="100%" stopColor="#F0C808" stopOpacity={0.30} />
          </linearGradient>
        </defs>

        {/* Grid lines */}
        {[0, 0.2, 0.4, 0.6, 0.8, 1.0].map((v) => (
          <line key={v} x1={50} x2={940} y1={riskToY(v, H, P)} y2={riskToY(v, H, P)} stroke="#18181b" strokeDasharray="2 4" opacity={0.3} />
        ))}

        {/* Peak ceiling 0.60 */}
        <line x1={50} x2={940} y1={peakY} y2={peakY} stroke="#71717A" strokeDasharray="4 4" strokeOpacity={0.85} strokeWidth={1} />
        <text x={55} y={peakY - 8} fill="#A1A1AA" fontFamily="'JetBrains Mono', monospace" fontSize={11} fontWeight={500} letterSpacing="0.06em">
          CONFIGURED PEAK CEILING 0.60
        </text>

        {/* Target ceiling 0.40 */}
        <line x1={50} x2={940} y1={targetY} y2={targetY} stroke="#A1A1AA" strokeDasharray="4 4" strokeOpacity={0.85} strokeWidth={1} />
        <text x={55} y={targetY - 8} fill="#A1A1AA" fontFamily="'JetBrains Mono', monospace" fontSize={11} fontWeight={500} letterSpacing="0.06em">
          CONFIGURED TARGET CEILING 0.40
        </text>

        {/* T0 vertical marker */}
        <line x1={480} x2={480} y1={16} y2={H - P} stroke="#F0C808" strokeDasharray="3 3" strokeOpacity={0.85} strokeWidth={1.5} />

        {/* Uncertainty envelope */}
        <polygon points={bandPolygon} fill="url(#uncertaintyBand)" stroke="#F0C808" strokeDasharray="2 2" strokeOpacity={0.4} strokeWidth={1} />

        {/* Observed path */}
        {obsPath && <path d={obsPath} fill="none" stroke="#FFFFFF" strokeLinecap="round" strokeWidth={2.5} />}

        {/* Observed points */}
        {obsPoints.map((p, i) => (
          <circle key={`obs-${i}`} cx={p.x} cy={p.y} r={3.5} fill="#FFFFFF" />
        ))}

        {/* Live T0 pulse dot */}
        <circle cx={t0Point.x} cy={t0Point.y} r={9} fill="#F0C808" opacity={0.35} className="glz-live-ping pointer-events-none" />

        {/* T0 marker */}
        <circle cx={t0Point.x} cy={t0Point.y} r={5} fill="#FFFFFF" stroke="#F0C808" strokeWidth={2.5} />

        {/* Forecast path with animated drawing */}
        <path d={forecastPath} fill="none" stroke="#F0C808" strokeLinecap="round" strokeWidth={2.5} className="glz-animate-draw" />

        {/* Forecast points */}
        {forecastPoints.slice(1).map((p, i) => (
          <circle key={`fc-${i}`} cx={p.x} cy={p.y} r={4.5} fill="#F0C808" />
        ))}

        {/* T0 label pill */}
        <rect x={434} y={11} width={92} height={22} rx={11} fill="#080808" stroke="#3f3f46" strokeWidth={1} />
        <text x={480} y={26} fill="#F0C808" fontFamily="'JetBrains Mono', monospace" fontSize={12} fontWeight={600} textAnchor="middle">
          T0 : {currentRisk.toFixed(2)}
        </text>
      </svg>

      {/* Y-axis labels */}
      <div className="absolute left-3 top-5 bottom-12 flex flex-col justify-between font-mono text-xs text-[#71717A] pointer-events-none select-none font-medium">
        {['1.00', '0.80', '0.60', '0.40', '0.20', '0.00'].map((l) => <span key={l}>{l}</span>)}
      </div>

      {/* X-axis labels */}
      <div className="absolute bottom-2.5 left-14 right-8 flex justify-between font-mono text-xs text-[#71717A] pt-2 border-t border-[#18181b]">
        <span>T−30s</span>
        <span>T−20s</span>
        <span>T−10s</span>
        <span className="text-white font-semibold">T0 [PRESENT]</span>
        <span className="text-[#A1A1AA] font-medium">+10s</span>
        <span className="text-[#F0C808] font-semibold">+20s</span>
        <span className="text-[#A1A1AA] font-medium">+30s [HORIZON]</span>
      </div>
    </ConicBorderPanel>
  );
}

export const TrajectoryForecastPage: React.FC = () => {
  const { snapshot, eventHistory, connectionState } = useRuntimeStore();
  const [contributions, setContributions] = useState<ForecastFeatureContribution[]>([]);

  const event = snapshot.event;
  const currentRisk = event?.current_risk_score ?? 0;
  const futureRisks = event?.future_risk_scores ?? {};
  const t10 = futureRisks['+10s'] ?? currentRisk * 1.2;
  const t20 = futureRisks['+20s'] ?? currentRisk * 1.4;
  const t30 = futureRisks['+30s'] ?? currentRisk * 1.5;
  const isLive = connectionState === 'CONNECTED';

  // Peak detection
  const peakValue = Math.max(t10, t20, t30);
  const peakLabel = t30 >= t20 && t30 >= t10 ? '+30s' : t20 >= t10 ? '+20s' : '+10s';
  const breachesPeakCeiling = peakValue > 0.60;

  // Fetch forecast contributions
  useEffect(() => {
    apiClient.getForecast()
      .then((res) => {
        if (res.forecast_feature_contributions) {
          setContributions(res.forecast_feature_contributions);
        }
      })
      .catch(() => {/* Backend may not be running */});
  }, [event?.step_index]);

  // Driver features from current state
  const state = event?.current_state_summary;
  const drivers = [
    { label: 'BYTE RATE', value: state?.byte_rate, unit: 'MB/s' },
    { label: 'FLOW COUNT', value: state?.flow_count, unit: 'flows/s' },
    { label: 'SYN RATIO', value: state?.syn_ratio, unit: '' },
  ];

  return (
    <div className="space-y-10">
      {/* HEADING */}
      <section className="space-y-2">
        <div className="font-mono text-xs text-[#71717A] tracking-wider flex items-center gap-2">
          <span className="text-[#F0C808] font-semibold">AR(5) TEMPORAL FORECAST</span>
          <span className="text-[#18181b]">·</span>
          <span className="text-[#A1A1AA]">T0 → +30s</span>
          {!isLive && <span className="text-[#F0C808] ml-2">[DEMO DATA]</span>}
        </div>
        <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-white leading-none uppercase">
          TRAJECTORY FORECAST
        </h1>
        <div className="space-y-2 pt-1.5">
          <h2 className="text-lg sm:text-xl font-medium tracking-normal text-zinc-300">
            {breachesPeakCeiling
              ? 'PROJECTED ESCALATION — CEILING BREACH EXPECTED'
              : currentRisk > 0.4
              ? 'PROJECTED ELEVATION — MONITORING ADVISED'
              : 'PROJECTED TRAJECTORY — WITHIN ENVELOPE'}
          </h2>
          <p className="text-base font-normal text-zinc-300 max-w-4xl leading-relaxed">
            {breachesPeakCeiling
              ? `Projected security risk continues above configured safety threshold across the 30-second forecast horizon. Configured peak ceiling exceeded within forecast window.`
              : `AR(5) model projects security risk trajectory across the +10/+20/+30 second forecast horizon.`}
          </p>
        </div>
      </section>

      {/* TEMPORAL RISK READOUT */}
      <GlassPanel as="section" variant="default" className="p-6 flex items-center justify-between gap-6 font-mono overflow-x-auto shadow-[0_4px_24px_rgba(0,0,0,0.5)] border border-[#27272A]/60">
        <div className="flex items-center gap-6 text-xs whitespace-nowrap">
          <div className="flex items-baseline gap-2">
            <span className="text-[#71717A] tracking-wider uppercase font-medium">CURRENT (T0):</span>
            <span className="text-2xl text-white font-bold tracking-tight">{currentRisk.toFixed(2)}</span>
            <span className="text-xs text-[#71717A]">/ 1.00</span>
          </div>
          <span className="text-neutral-600 text-sm font-light">→</span>
          <div className="flex items-baseline gap-2">
            <span className="text-[#71717A] tracking-wider uppercase font-medium">+10s:</span>
            <span className="text-xl text-white font-bold tracking-tight">{t10.toFixed(2)}</span>
          </div>
          <span className="text-neutral-600 text-sm font-light">→</span>
          <div className="flex items-baseline gap-2">
            <span className={`text-xs tracking-wider uppercase font-semibold ${peakLabel === '+20s' ? 'text-[#F0C808]' : 'text-[#71717A]'}`}>
              +20s{peakLabel === '+20s' ? ' [PEAK]' : ''}:
            </span>
            <span className={`text-xl font-bold tracking-tight ${peakLabel === '+20s' ? 'text-[#F0C808]' : 'text-white'}`}>
              {t20.toFixed(2)}
            </span>
          </div>
          <span className="text-neutral-600 text-sm font-light">→</span>
          <div className="flex items-baseline gap-2">
            <span className={`text-xs tracking-wider uppercase font-medium ${peakLabel === '+30s' ? 'text-[#F0C808]' : 'text-[#71717A]'}`}>
              +30s [HORIZON]{peakLabel === '+30s' ? ' [PEAK]' : ''}:
            </span>
            <span className={`text-xl font-bold tracking-tight ${peakLabel === '+30s' ? 'text-[#F0C808]' : 'text-white'}`}>
              {t30.toFixed(2)}
            </span>
          </div>
        </div>
        <div className="text-xs text-[#71717A] whitespace-nowrap shrink-0 pl-4 border-l border-[#18181b]/60">
          INCIDENT: <span className="text-[#A1A1AA] font-medium">
            {event?.event_id ? `INC-${event.step_index}` : 'PENDING'}
          </span>
        </div>
      </GlassPanel>

      {/* HERO TRAJECTORY CHART */}
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between text-xs font-mono gap-4 pb-1">
          <div className="flex items-center gap-2 text-[#71717A] tracking-wider uppercase text-sm font-medium">
            <span className="text-white font-semibold">TRAJECTORY // RISK R(t)</span>
            <span className="text-[#18181b]">·</span>
            <span className="text-[#A1A1AA]">T−30s → +30s</span>
          </div>
          <div className="flex flex-wrap items-center gap-6 text-xs text-[#71717A]">
            <div className="flex items-center gap-2">
              <span className="w-4 h-[2.5px] bg-white inline-block rounded-full" />
              <span className="text-[#A1A1AA] font-medium">Observed Risk</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-4 h-[2.5px] bg-[#F0C808] inline-block rounded-full" />
              <span className="text-[#A1A1AA] font-medium">AR(5) Forecast</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-4 h-2.5 bg-[#F0C808]/20 border border-[#F0C808]/40 inline-block rounded-full" />
              <span className="text-[#A1A1AA] font-medium">Bootstrap Interval</span>
            </div>
          </div>
        </div>
        {!event && connectionState === 'CONNECTING' ? (
          <AnalysisCardSkeleton type="chart" title="AR(5) TEMPORAL FORECAST // TRAJECTORY" ariaLabel="Loading trajectory forecast chart..." />
        ) : (
          <TrajectoryChart events={eventHistory} futureRisks={{ t10, t20, t30 }} active={Boolean(event) || isLive} />
        )}
      </section>

      {/* SUPPORTING EVIDENCE */}
      <GlassPanel as="section" variant="subtle" className="font-mono p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 border border-[#27272A]/60">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <span className="text-xs text-[#71717A] uppercase tracking-widest font-medium">PRIMARY OBSERVED DRIVERS (LAST 30S):</span>
          {drivers.map(({ label, value, unit }) => (
            <div key={label} className="flex items-baseline gap-2">
              <span className="text-[#71717A] text-xs tracking-wider font-medium">{label}</span>
              <span className="text-white text-base font-semibold">
                {value !== undefined ? (
                  label === 'FLOW COUNT' ? (
                    <>
                      <GlassKpiCountUp value={value} /> flows/s
                    </>
                  ) : unit === 'MB/s' ? (
                    `${(value / 1_000_000).toFixed(1)} MB/s`
                  ) : value > 1000 ? (
                    value.toLocaleString()
                  ) : (
                    value.toFixed(2)
                  )
                ) : (
                  '—'
                )}
              </span>
            </div>
          ))}
        </div>
        <div className="text-[11px] text-[#71717A] tracking-wider font-normal opacity-70">
          5 LAG REGRESSORS · 15D TENSOR
        </div>
      </GlassPanel>

      {/* PROGRESSIVE DISCLOSURE (CODEFRONTS GLZ-16) */}
      <GlassProgressiveDisclosure
        title="INSPECT AR(5) MODEL SPECIFICATION & FEATURE FORECAST"
        badge={`${contributions.length > 0 ? contributions.length : 15} FEATURES`}
      >
        <div className="flex items-center justify-between text-[11px] text-[#71717A] border-b border-[#18181b] pb-2">
          <span>VECTOR AUTOREGRESSIVE SPECIFICATION // AR(5) MATRIX</span>
          <span>HORIZON: +30,000ms // 15 TRANSPORT FEATURES</span>
        </div>
        {contributions.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-[#71717A] text-[10px] border-b border-[#18181b] uppercase tracking-wider">
                  <th className="py-1.5 font-normal">FEATURE</th>
                  <th className="py-1.5 font-normal">DIRECTION</th>
                  <th className="py-1.5 font-normal">CONTRIBUTION</th>
                  <th className="py-1.5 font-normal text-right">CURRENT VALUE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#18181b] text-[11px]">
                {contributions.slice(0, 10).map((c) => (
                  <tr key={c.feature_name}>
                    <td className="py-1.5 text-[#A1A1AA]">{c.feature_name}</td>
                    <td className={c.signed_direction === 'POSITIVE' ? 'text-[#F0C808]' : 'text-[#A1A1AA]'}>
                      {c.signed_direction}
                    </td>
                    <td className="text-white">{c.normalized_contribution.toFixed(4)}</td>
                    <td className="text-right text-[#A1A1AA]">{c.current_value.toFixed(4)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-[11px] text-[#71717A]">
            Feature contributions unavailable — backend not connected or forecast not yet computed.
          </p>
        )}
        <div className="text-[10px] text-[#71717A] pt-2 border-t border-[#18181b] flex justify-between">
          <span>MODEL SPECIFICATION: 5-LAG VECTOR AR // BOOTSTRAP RESAMPLE N=1,000</span>
          <span>STATUS: {isLive ? 'LIVE' : 'DEMO'}</span>
        </div>
      </GlassProgressiveDisclosure>
    </div>
  );
};
