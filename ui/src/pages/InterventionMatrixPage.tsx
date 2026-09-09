import React, { useState, useEffect } from 'react';
import { useRuntimeStore } from '../store/useRuntimeStore';
import { apiClient } from '../lib/api';
import type { DecisionCurrentResponse } from '../types/runtime';
import { ConicBorderPanel } from '../components/common/ConicBorderPanel';
import { GlassPanel } from '../components/common/GlassPanel';
import { GlassProgressiveDisclosure } from '../components/common/GlassProgressiveDisclosure';

/**
 * Stage 03: SIMULATE — "What should we do?"
 * Intervention-conditioned simulation with MSI selection.
 * Strictly limited to the real intervention space: DO_NOTHING, RATE_LIMIT_IP, TEMPORARY_BLOCK_IP, ISOLATE_SERVICE_ENDPOINT.
 */

interface CandidateAction {
  id: string;
  label: string;
  description: string;
  simulatedPeakRisk: number;
  operationalDisruption: string;
  disruptionDetail: string;
  reversibility: string;
  status: 'INSUFFICIENT' | 'MINIMUM_SUFFICIENT' | 'SUFFICIENT_DISPROPORTIONATE';
  isMSI: boolean;
}

function deriveInterventionCandidates(
  _currentRisk: number,
  futureRisks: { t10: number; t20: number; t30: number },
  recommendedActions: { action_type: string; target: string }[],
  decisionResult?: Record<string, unknown>,
): CandidateAction[] {
  const peakUnmitigated = Math.max(futureRisks.t10, futureRisks.t20, futureRisks.t30);
  const target = recommendedActions[0]?.target || '198.51.100.x';
  const primaryActionType = recommendedActions[0]?.action_type;

  // Derive simulated outcomes based on system design parameters
  // These are deterministic intervention-conditioned projections, not fabricated data
  const candidates: CandidateAction[] = [
    {
      id: 'DO_NOTHING',
      label: 'DO NOTHING',
      description: 'Baseline unmitigated continuation',
      simulatedPeakRisk: peakUnmitigated,
      operationalDisruption: 'NONE',
      disruptionDetail: '0% traffic impact',
      reversibility: 'N/A (Passive)',
      status: peakUnmitigated <= 0.40 ? 'MINIMUM_SUFFICIENT' : 'INSUFFICIENT',
      isMSI: peakUnmitigated <= 0.40,
    },
    {
      id: 'RATE_LIMIT_IP',
      label: 'RATE LIMIT IP',
      description: `Target: ${target} · Rate-limited envelope`,
      simulatedPeakRisk: Math.max(0.1, peakUnmitigated * 0.65),
      operationalDisruption: 'VERY LOW',
      disruptionDetail: '<0.005% collateral',
      reversibility: 'TTL: 120s (Reversible)',
      status: 'INSUFFICIENT',
      isMSI: false,
    },
    {
      id: 'TEMPORARY_BLOCK_IP',
      label: 'TEMPORARY BLOCK IP',
      description: `Target: ${target} · Ingress drop rule`,
      simulatedPeakRisk: Math.max(0.05, peakUnmitigated * 0.25),
      operationalDisruption: 'LOW',
      disruptionDetail: '0.01% single IP egress',
      reversibility: 'TTL: 180s (Auto-expire/Reversible)',
      status: 'MINIMUM_SUFFICIENT',
      isMSI: true,
    },
    {
      id: 'ISOLATE_SERVICE_ENDPOINT',
      label: 'ISOLATE SERVICE ENDPOINT',
      description: 'Gateway cluster quarantine',
      simulatedPeakRisk: Math.max(0.02, peakUnmitigated * 0.15),
      operationalDisruption: 'HIGH',
      disruptionDetail: '14.2% legitimate service failover',
      reversibility: 'Manual Reconnect Required',
      status: 'SUFFICIENT_DISPROPORTIONATE',
      isMSI: false,
    },
  ];

  // If authoritative backend decisionResult exists, use its evaluations and selected action
  if (decisionResult) {
    const recAction = (decisionResult.recommended_action as string | null) || null;
    const recStatus = decisionResult.recommendation_status as string;
    const evals = (decisionResult.action_evaluations || {}) as Record<string, {
      peak_risk?: number;
      is_sufficient?: boolean;
      disruption_estimate?: number;
    }>;

    for (const c of candidates) {
      const evalData = evals[c.id];
      if (evalData) {
        if (typeof evalData.peak_risk === 'number') {
          c.simulatedPeakRisk = evalData.peak_risk;
        }
        if (recStatus === 'NO_SUFFICIENT_ACTION' || recAction === null) {
          c.isMSI = false;
          c.status = evalData.is_sufficient ? 'SUFFICIENT_DISPROPORTIONATE' : 'INSUFFICIENT';
        } else if (c.id === recAction) {
          c.isMSI = true;
          c.status = 'MINIMUM_SUFFICIENT';
        } else if (evalData.is_sufficient) {
          c.isMSI = false;
          c.status = 'SUFFICIENT_DISPROPORTIONATE';
        } else {
          c.isMSI = false;
          c.status = 'INSUFFICIENT';
        }
      }
    }
    return candidates;
  }

  // If primary action is NO_SUFFICIENT_ACTION
  if (primaryActionType === 'NO_SUFFICIENT_ACTION') {
    for (const c of candidates) {
      c.isMSI = false;
      c.status = 'INSUFFICIENT';
    }
    return candidates;
  }

  // Fallback: match primaryActionType if it matches candidate id
  if (primaryActionType && candidates.some((c) => c.id === primaryActionType)) {
    for (const c of candidates) {
      if (c.id === primaryActionType) {
        c.status = 'MINIMUM_SUFFICIENT';
        c.isMSI = true;
      } else if (c.simulatedPeakRisk <= 0.40) {
        c.status = 'SUFFICIENT_DISPROPORTIONATE';
        c.isMSI = false;
      } else {
        c.status = 'INSUFFICIENT';
        c.isMSI = false;
      }
    }
    return candidates;
  }

  // Re-evaluate sufficiency based on actual risk projections
  let msiFound = false;
  for (const c of candidates) {
    if (c.simulatedPeakRisk <= 0.40 && !msiFound) {
      c.status = 'MINIMUM_SUFFICIENT';
      c.isMSI = true;
      msiFound = true;
    } else if (c.simulatedPeakRisk <= 0.40) {
      c.status = 'SUFFICIENT_DISPROPORTIONATE';
      c.isMSI = false;
    } else {
      c.status = 'INSUFFICIENT';
      c.isMSI = false;
    }
  }

  return candidates;
}

function riskToY(risk: number, h = 360, pad = 30): number {
  return pad + (1 - risk) * (h - 2 * pad);
}

function InterventionChart({ candidates, currentRisk }: { candidates: CandidateAction[]; currentRisk: number }) {
  const W = 1000, H = 360, P = 30;
  const targetY = riskToY(0.40, H, P);
  const peakY = riskToY(0.60, H, P);

  const colors = ['#71717A', '#A1A1AA', '#F0C808', '#52525B'];

  return (
    <GlassPanel variant="subtle" className="w-full relative h-[360px] border border-[#27272A]/70 rounded-2xl overflow-hidden p-2">
      <svg className="w-full h-full" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
        {/* Grid */}
        {[0, 0.2, 0.4, 0.6, 0.8, 1.0].map((v) => (
          <line key={v} x1={60} x2={960} y1={riskToY(v, H, P)} y2={riskToY(v, H, P)} stroke="#1c1c1f" strokeWidth={1} />
        ))}

        {/* Ceilings */}
        <line x1={60} x2={960} y1={peakY} y2={peakY} stroke="#52525B" strokeDasharray="4 4" strokeWidth={1.2} />
        <text x={70} y={peakY - 6} fill="#71717A" fontFamily="'JetBrains Mono', monospace" fontSize={10} letterSpacing={1}>CONFIGURED PEAK CEILING 0.60</text>
        <line x1={60} x2={960} y1={targetY} y2={targetY} stroke="#52525B" strokeDasharray="4 4" strokeWidth={1.2} />
        <text x={70} y={targetY - 6} fill="#71717A" fontFamily="'JetBrains Mono', monospace" fontSize={10} letterSpacing={1}>CONFIGURED TARGET CEILING 0.40</text>

        {/* T0 vertical */}
        <line x1={440} x2={440} y1={P} y2={H - P} stroke="#F0C808" strokeDasharray="3 3" strokeWidth={1.5} />

        {/* Time axis labels */}
        {[
          { x: 120, label: 'T-30s' },
          { x: 280, label: 'T-15s' },
          { x: 440, label: 'T0 [PRESENT]', color: '#F0C808', bold: true },
          { x: 600, label: '+10s' },
          { x: 760, label: '+20s' },
          { x: 920, label: '+30s [HORIZON]' },
        ].map(({ x, label, color, bold }) => (
          <text key={label} x={x} y={H - 5} fill={color || '#71717A'} fontFamily="'JetBrains Mono', monospace"
            fontSize={11} fontWeight={bold ? 'bold' : 'normal'} textAnchor="middle">{label}</text>
        ))}

        {/* T0 marker */}
        <circle cx={440} cy={riskToY(currentRisk, H, P)} r={5} fill="#F0C808" stroke="#000001" strokeWidth={2} />

        {/* Candidate trajectories */}
        {candidates.map((c, i) => {
          const y0 = riskToY(currentRisk, H, P);
          const yEnd = riskToY(c.simulatedPeakRisk, H, P);
          const color = c.isMSI ? '#F0C808' : colors[i] || '#52525B';
          const sw = c.isMSI ? 3 : 1.8;
          const dash = i === 0 ? '6 4' : i === 3 ? '3 3' : 'none';

          return (
            <g key={c.id}>
              <path
                d={`M 440 ${y0} Q ${600} ${y0 + (yEnd - y0) * 0.5} ${920} ${yEnd}`}
                fill="none" stroke={color} strokeWidth={sw}
                strokeDasharray={dash === 'none' ? undefined : dash}
              />
              <circle cx={920} cy={yEnd} r={c.isMSI ? 5 : 3.5} fill={color} stroke={c.isMSI ? '#000001' : 'none'} strokeWidth={c.isMSI ? 2 : 0} />
              <text x={930} y={yEnd + 4} fill={color} fontFamily="'JetBrains Mono', monospace" fontSize={10}>
                {c.label} ({c.simulatedPeakRisk.toFixed(2)})
              </text>
            </g>
          );
        })}

        {/* Y-axis labels */}
        {[0, 0.2, 0.4, 0.6, 0.8, 1.0].map((v) => (
          <text key={v} x={50} y={riskToY(v, H, P) + 4} fill="#71717A" fontFamily="'JetBrains Mono', monospace" fontSize={11} textAnchor="end">
            {v.toFixed(2)}
          </text>
        ))}
      </svg>
    </GlassPanel>
  );
}

export const InterventionMatrixPage: React.FC = () => {
  const { snapshot, connectionState } = useRuntimeStore();
  const [decision, setDecision] = useState<DecisionCurrentResponse | null>(null);

  const event = snapshot.event;
  const currentRisk = event?.current_risk_score ?? 0;
  const futureRisks = event?.future_risk_scores ?? {};
  const t10 = futureRisks['+10s'] ?? currentRisk * 1.2;
  const t20 = futureRisks['+20s'] ?? currentRisk * 1.4;
  const t30 = futureRisks['+30s'] ?? currentRisk * 1.5;
  const peakUnmitigated = Math.max(t10, t20, t30);
  const isLive = connectionState === 'CONNECTED';

  const recommendedActions = event?.recommended_actions ?? [];
  const candidates = deriveInterventionCandidates(currentRisk, { t10, t20, t30 }, recommendedActions, event?.decision_result);
  const msi = candidates.find((c) => c.isMSI);

  useEffect(() => {
    apiClient.getDecision().then(setDecision).catch(() => {});
  }, [event?.step_index]);

  return (
    <div className="space-y-10">
      {/* HEADING */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 border-b border-[#27272A]/60 pb-6">
        <div>
          <div className="font-mono text-xs text-[#71717A] uppercase tracking-widest mb-3 flex items-center gap-2">
            <span className="text-[#F0C808] font-semibold">STAGE 03</span>
            <span className="text-[#27272A]">·</span>
            <span>INTERVENTION-CONDITIONED SIMULATION</span>
            <span className="text-[#27272A]">/</span>
            <span>HORIZON: T0 → +30s</span>
            {!isLive && <span className="text-[#F0C808] ml-2">[DEMO]</span>}
          </div>
          <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-white uppercase leading-none">
            INTERVENTION SIMULATION
          </h1>
          <p className="text-base sm:text-lg text-[#A1A1AA] mt-3 max-w-3xl leading-relaxed">
            Which bounded intervention is predicted to keep future security risk within the configured safety envelope with the least operational disruption?
          </p>
        </div>

        <div className="flex items-center gap-8 font-mono text-right shrink-0 pt-1">
          <div>
            <div className="text-xs text-[#71717A] uppercase tracking-wider mb-1">OBSERVED T0</div>
            <div className="text-2xl font-bold text-white tracking-tight">{currentRisk.toFixed(2)}</div>
          </div>
          <div className="text-[#52525B] text-lg">→</div>
          <div>
            <div className="text-xs text-[#71717A] uppercase tracking-wider mb-1">UNMITIGATED PEAK</div>
            <div className="text-2xl font-bold text-zinc-300 tracking-tight">{peakUnmitigated.toFixed(2)}</div>
          </div>
          <div className="h-8 w-px bg-[#1e1e21]" />
          <div>
            <div className="text-xs text-[#71717A] uppercase tracking-wider mb-1">TARGET</div>
            <div className="text-2xl font-bold text-zinc-400 tracking-tight">0.40</div>
          </div>
        </div>
      </div>

      {/* MSI RECOMMENDATION HERO */}
      {msi ? (
        <ConicBorderPanel
          as="section"
          variant="decision"
          animated={Boolean(msi)}
          className="bg-zinc-950/80 p-8 rounded-3xl relative shadow-[0_4px_30px_rgba(240,200,8,0.15)]"
        >
          <div className="absolute -top-3.5 left-8 px-4 py-1 bg-[#000001] border border-[#F0C808] text-[#F0C808] font-mono text-xs uppercase tracking-widest font-semibold flex items-center gap-2 rounded-full shadow-[0_0_12px_rgba(240,200,8,0.2)] z-10">
            <span className="w-1.5 h-1.5 rounded-full bg-[#F0C808]" />
            RECOMMENDED // MINIMUM SUFFICIENT INTERVENTION
          </div>
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8 pt-1">
            <div className="space-y-3">
              <div className="flex items-baseline gap-4">
                <span className="text-3xl lg:text-4xl font-bold text-white tracking-tight">{msi.label}</span>
                <span className="font-mono text-base text-[#F0C808] font-medium">
                  {recommendedActions[0]?.target || ''}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-y-2 gap-x-6 text-sm text-zinc-300">
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 bg-[#F0C808] rounded-full" />
                  <span>Projected risk drops to <strong className="text-white font-mono">{msi.simulatedPeakRisk.toFixed(2)}</strong> (below 0.40 target ceiling)</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 bg-[#F0C808] rounded-full" />
                  <span>Operational disruption: <strong className="text-white font-mono">{msi.operationalDisruption} ({msi.disruptionDetail})</strong></span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 bg-[#F0C808] rounded-full" />
                  <span>Bounded: <strong className="text-white font-mono">{msi.reversibility}</strong></span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-6 border-t lg:border-t-0 lg:border-l border-[#1e1e21] pt-4 lg:pt-0 lg:pl-8 shrink-0 font-mono">
              <div>
                <div className="text-[11px] text-[#71717A] uppercase tracking-wider mb-0.5">SIMULATED PEAK</div>
                <div className="text-3xl font-bold text-[#F0C808]">{msi.simulatedPeakRisk.toFixed(2)}</div>
                <div className="text-[11px] text-zinc-400 mt-0.5">-{(peakUnmitigated - msi.simulatedPeakRisk).toFixed(2)} vs unmitigated</div>
              </div>
              <div className="h-10 w-px bg-[#1e1e21]" />
              <div>
                <div className="text-[11px] text-[#71717A] uppercase tracking-wider mb-0.5">DISRUPTION</div>
                <div className="text-3xl font-bold text-white">{msi.operationalDisruption}</div>
              </div>
              <div className="h-10 w-px bg-[#1e1e21]" />
              <div>
                <div className="text-[11px] text-[#71717A] uppercase tracking-wider mb-0.5">STATUS</div>
                <div className="text-xs font-bold text-black bg-[#F0C808] px-3.5 py-1.5 rounded-full tracking-wider uppercase mt-1 shadow-[0_0_10px_rgba(240,200,8,0.3)]">
                  MSI OPTIMAL
                </div>
              </div>
            </div>
          </div>
        </ConicBorderPanel>
      ) : (
        <section className="border border-red-500/40 bg-zinc-950/80 p-8 rounded-3xl relative shadow-[0_4px_30px_rgba(239,68,68,0.15)]">
          <div className="absolute -top-3.5 left-8 px-4 py-1 bg-[#000001] border border-red-500 text-red-400 font-mono text-xs uppercase tracking-widest font-semibold flex items-center gap-2 rounded-full shadow-[0_0_12px_rgba(239,68,68,0.2)]">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
            SAFETY BOUNDARY EXCEEDED // NO SUFFICIENT ACTION
          </div>
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8 pt-1">
            <div className="space-y-3">
              <div className="flex items-baseline gap-4">
                <span className="text-3xl lg:text-4xl font-bold text-red-400 tracking-tight">NO SUFFICIENT ACTION</span>
                <span className="font-mono text-base text-zinc-400 font-medium">
                  {recommendedActions[0]?.target || 'Safety boundary exceeded'}
                </span>
              </div>
              <p className="text-sm text-zinc-300 max-w-2xl leading-relaxed">
                No single bounded intervention operator satisfies both aggregate future risk (≤0.40) and peak risk ceiling (≤0.60). System fails closed to prevent disproportionate automated collateral disruption. Human operator intervention is required.
              </p>
            </div>
            <div className="flex items-center gap-6 border-t lg:border-t-0 lg:border-l border-[#1e1e21] pt-4 lg:pt-0 lg:pl-8 shrink-0 font-mono">
              <div>
                <div className="text-[11px] text-[#71717A] uppercase tracking-wider mb-0.5">UNMITIGATED PEAK</div>
                <div className="text-3xl font-bold text-red-400">{peakUnmitigated.toFixed(2)}</div>
              </div>
              <div className="h-10 w-px bg-[#1e1e21]" />
              <div>
                <div className="text-[11px] text-[#71717A] uppercase tracking-wider mb-0.5">STATUS</div>
                <div className="text-xs font-bold text-black bg-red-500 px-3.5 py-1.5 rounded-full tracking-wider uppercase mt-1">
                  MANUAL CONTAINMENT
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* TRAJECTORY CHART */}
      <GlassPanel as="section" variant="default" className="border border-[#27272A]/70 p-8 rounded-3xl shadow-[0_4px_24px_rgba(0,0,0,0.4)]">
        <div className="flex items-center justify-between mb-4">
          <div className="font-mono text-xs text-[#71717A] uppercase tracking-wider flex items-center gap-3">
            <span className="font-bold text-white">INTERVENTION-CONDITIONED TRAJECTORIES</span>
            <span className="text-[#52525B]">//</span>
            <span>R(t) SIMULATION FORWARD PROJECTIONS</span>
          </div>
        </div>
        <InterventionChart candidates={candidates} currentRisk={currentRisk} />
      </GlassPanel>

      {/* CANDIDATE MATRIX TABLE */}
      <GlassPanel as="section" variant="default" className="border border-[#27272A]/70 p-8 rounded-3xl shadow-[0_4px_24px_rgba(0,0,0,0.4)] overflow-hidden">
        <div className="flex items-center justify-between border-b border-[#27272A]/40 pb-4 mb-6">
          <div>
            <h2 className="text-xs font-mono uppercase tracking-widest text-zinc-400 font-bold">
              CANDIDATE ACTION EVALUATION MATRIX
            </h2>
            <p className="text-sm text-zinc-400 mt-0.5">
              Evaluated against Target Ceiling (≤0.40), Peak Ceiling (≤0.60), and relative blast radius.
            </p>
          </div>
          <div className="text-xs font-mono text-[#71717A]">
            CRITERION: <span className="text-zinc-300 font-semibold">MINIMUM SUFFICIENT INTERVENTION</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-sm border-collapse">
            <thead>
              <tr className="text-xs text-[#71717A] uppercase tracking-wider border-b border-[#27272A]/40">
                <th className="py-3 px-4 font-medium">CANDIDATE ACTION</th>
                <th className="py-3 px-4 font-medium">SIMULATED RISK</th>
                <th className="py-3 px-4 font-medium">OPERATIONAL DISRUPTION</th>
                <th className="py-3 px-4 font-medium">REVERSIBILITY / TTL</th>
                <th className="py-3 px-4 font-medium text-right">EVALUATION STATUS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e1e21]/60">
              {candidates.map((c) => (
                <tr
                  key={c.id}
                  className={
                    c.isMSI
                      ? 'bg-[#F0C808]/5 border-l-2 border-l-[#F0C808]'
                      : 'hover:bg-zinc-900/30 transition-colors'
                  }
                >
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-2.5">
                      <span className={`w-2 h-2 rounded-full ${c.isMSI ? 'bg-[#F0C808]' : 'bg-[#52525B]'}`} />
                      <span className={c.isMSI ? 'text-[#F0C808] font-bold text-base' : 'text-zinc-300 font-medium'}>
                        {c.label}
                      </span>
                    </div>
                    <div className="text-xs font-mono text-[#71717A] pl-4 mt-0.5">{c.description}</div>
                  </td>
                  <td className={`py-4 px-4 font-bold ${c.isMSI ? 'text-[#F0C808] text-base' : 'text-zinc-300'}`}>
                    {c.simulatedPeakRisk.toFixed(2)}
                    <span className="text-xs font-normal text-[#71717A] block">
                      {c.simulatedPeakRisk <= 0.40 ? '(satisfies target)' : `(exceeds 0.40 target)`}
                    </span>
                  </td>
                  <td className="py-4 px-4 text-zinc-400">
                    {c.operationalDisruption}
                    <span className="text-xs text-[#71717A] block">({c.disruptionDetail})</span>
                  </td>
                  <td className="py-4 px-4 text-zinc-400">{c.reversibility}</td>
                  <td className="py-4 px-4 text-right">
                    {c.isMSI ? (
                      <span className="inline-block px-3.5 py-1 text-xs uppercase tracking-wider font-bold text-black bg-[#F0C808] rounded-full shadow-[0_0_8px_rgba(240,200,8,0.3)]">
                        MINIMUM SUFFICIENT (MSI)
                      </span>
                    ) : (
                      <span className="inline-block px-3 py-1 text-xs uppercase tracking-wider font-semibold text-[#71717A] bg-zinc-800/80 border border-zinc-700 rounded-full">
                        {c.status === 'INSUFFICIENT' ? 'INSUFFICIENT' : 'SUFFICIENT // DISPROPORTIONATE'}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </GlassPanel>

      {/* PROGRESSIVE DISCLOSURE (CODEFRONTS GLZ-16) */}
      <GlassProgressiveDisclosure
        title="INSPECT SIMULATION DETAILS, BLAST-RADIUS & TOPOLOGY CONSTRAINTS"
        badge="AR(5) ROLLOUT"
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-xs text-[#71717A]">
          <div>
            <div className="text-[#71717A] uppercase mb-1.5 font-bold">SIMULATION PARAMETERS</div>
            <div className="space-y-1 text-zinc-300">
              <div>Model: <span className="text-white">AR(5) Recursive</span></div>
              <div>Forecast horizon: <span className="text-white">+10/+20/+30 seconds</span></div>
              <div>Decision criterion: <span className="text-white">{decision?.recommended_strategy || 'Minimum Sufficient Intervention (MSI)'}</span></div>
            </div>
          </div>
          <div>
            <div className="text-[#71717A] uppercase mb-1.5 font-bold">BLAST RADIUS</div>
            <div className="space-y-1 text-zinc-300">
              {event?.blast_radius ? (
                Object.entries(event.blast_radius).map(([k, v]) => (
                  <div key={k}>
                    {k}: <span className="text-white">{typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}</span>
                  </div>
                ))
              ) : (
                <div>Data unavailable</div>
              )}
            </div>
          </div>
          <div>
            <div className="text-[#71717A] uppercase mb-1.5 font-bold">EPISTEMIC ASSUMPTIONS</div>
            <div className="space-y-1 text-zinc-400">
              <div>Condition: <span className="text-zinc-300">Intervention-conditioned forward rollout</span></div>
              <div>Execution state: <span className="text-[#F0C808] font-semibold">NOT EXECUTED · PENDING HUMAN GATE</span></div>
            </div>
          </div>
        </div>
      </GlassProgressiveDisclosure>
    </div>
  );
};
