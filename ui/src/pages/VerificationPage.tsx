import React, { useState, useEffect } from 'react';
import { useRuntimeStore } from '../store/useRuntimeStore';
import { apiClient } from '../lib/api';
import type { ResponseExecutionResponse, DemoEvent } from '../types/runtime';
import { AnalysisCardSkeleton } from '../components/common/ShimmerSkeletons';
import { GlassPanel } from '../components/common/GlassPanel';
import { GlassProgressiveDisclosure } from '../components/common/GlassProgressiveDisclosure';

/**
 * Stage 05: VERIFY — "Did the intervention work?"
 * Post-execution verification comparing expected vs observed outcomes.
 * Derives verification state from runtime store event data.
 */

function riskToY(risk: number, h = 240, pad = 20): number {
  return pad + (1 - risk) * (h - 2 * pad);
}

function VerificationChart({ events, executionStep }: { events: DemoEvent[]; executionStep: number }) {
  const W = 960, H = 240, P = 20;
  const targetY = riskToY(0.40, H, P);

  // Pre-execution events
  const preEvents = events.filter((e) => e.step_index <= executionStep);
  const postEvents = events.filter((e) => e.step_index > executionStep);

  const allRelevant = [...preEvents.slice(-3), ...postEvents.slice(0, 4)];
  if (allRelevant.length === 0) return null;

  const points = allRelevant.map((e, i) => ({
    x: 80 + (i / Math.max(allRelevant.length - 1, 1)) * (W - 120),
    y: riskToY(e.current_risk_score, H, P),
    r: e.current_risk_score,
    isPost: e.step_index > executionStep,
    step: e.step_index,
  }));

  const prePoints = points.filter((p) => !p.isPost);
  const postPoints = points.filter((p) => p.isPost);

  const prePath = prePoints.length > 1
    ? `M ${prePoints.map((p) => `${p.x},${p.y}`).join(' L ')}`
    : '';
  const postPath = postPoints.length > 1
    ? `M ${postPoints.map((p) => `${p.x},${p.y}`).join(' L ')}`
    : '';

  // Connect pre to post
  const bridgePath = prePoints.length > 0 && postPoints.length > 0
    ? `M ${prePoints[prePoints.length - 1].x},${prePoints[prePoints.length - 1].y} L ${postPoints[0].x},${postPoints[0].y}`
    : '';

  const execX = prePoints.length > 0 ? prePoints[prePoints.length - 1].x : 400;

  return (
    <GlassPanel variant="default" className="relative w-full h-72 p-6 overflow-hidden select-none shadow-[0_4px_24px_rgba(0,0,0,0.4)] border border-[#27272A]/70">
      <svg className="w-full h-full" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
        {[0, 0.2, 0.4, 0.6, 0.8, 1.0].map((v) => (
          <line key={v} x1={60} x2={920} y1={riskToY(v, H, P)} y2={riskToY(v, H, P)} stroke="#18181b" strokeWidth={1} opacity={0.3} />
        ))}

        {/* Target ceiling */}
        <line x1={60} x2={920} y1={targetY} y2={targetY} stroke="#A1A1AA" strokeDasharray="4 4" strokeWidth={1} />
        <text x={65} y={targetY - 7} fill="#71717A" fontFamily="'JetBrains Mono', monospace" fontSize={10}>TARGET 0.40</text>

        {/* Execution marker */}
        <line x1={execX} x2={execX} y1={P} y2={H - P} stroke="#F0C808" strokeDasharray="3 3" strokeWidth={1.5} />
        <text x={execX + 5} y={P + 12} fill="#F0C808" fontFamily="'JetBrains Mono', monospace" fontSize={10} fontWeight={600}>EXECUTION</text>

        {/* Pre path (white) */}
        {prePath && <path d={prePath} fill="none" stroke="#FFFFFF" strokeWidth={2} className="glz-animate-draw" />}
        {prePoints.map((p, i) => <circle key={`pre-${i}`} cx={p.x} cy={p.y} r={3} fill="#FFFFFF" />)}

        {/* Bridge (dashed) */}
        {bridgePath && <path d={bridgePath} fill="none" stroke="#F0C808" strokeDasharray="4 3" strokeWidth={1.5} />}

        {/* Post path (green if descending, red if not) */}
        {postPath && (
          <path d={postPath} fill="none"
            stroke={postPoints.length > 0 && postPoints[postPoints.length - 1].r <= 0.40 ? '#22c55e' : '#ef4444'}
            strokeWidth={2.5}
            className="glz-animate-draw"
          />
        )}
        {postPoints.map((p, i) => (
          <circle key={`post-${i}`} cx={p.x} cy={p.y} r={4}
            fill={p.r <= 0.40 ? '#22c55e' : '#ef4444'} stroke="#000001" strokeWidth={1.5}
          />
        ))}

        {/* Live marker on the most recent observed post point */}
        {postPoints.length > 0 && (
          <circle
            cx={postPoints[postPoints.length - 1].x}
            cy={postPoints[postPoints.length - 1].y}
            r={8}
            fill={postPoints[postPoints.length - 1].r <= 0.40 ? '#22c55e' : '#ef4444'}
            opacity={0.35}
            className="glz-live-ping pointer-events-none"
          />
        )}
      </svg>

      {/* Y-axis labels */}
      <div className="absolute left-3 top-5 bottom-8 flex flex-col justify-between font-mono text-xs text-[#71717A] pointer-events-none">
        {['1.00', '0.80', '0.60', '0.40', '0.20', '0.00'].map((l) => <span key={l}>{l}</span>)}
      </div>
      {/* X-axis */}
      <div className="absolute bottom-2 left-16 right-8 flex justify-between font-mono text-xs text-[#71717A] pt-2 border-t border-[#27272A]/40">
        <span>PRE-EXECUTION</span>
        <span className="text-[#F0C808]">⬍ EXECUTION POINT</span>
        <span>POST-EXECUTION (OBSERVED)</span>
      </div>
    </GlassPanel>
  );
}

export const VerificationPage: React.FC = () => {
  const { snapshot, eventHistory, connectionState } = useRuntimeStore();
  const [responseHistory, setResponseHistory] = useState<ResponseExecutionResponse[]>([]);

  const event = snapshot.event;
  const isLive = connectionState === 'CONNECTED';
  const reconsideration = snapshot.reconsideration;

  // Fetch response history
  useEffect(() => {
    apiClient.getResponseHistory().then(setResponseHistory).catch(() => {});
  }, [event?.step_index]);

  const latestExecution = responseHistory.length > 0 ? responseHistory[responseHistory.length - 1] : null;
  const executionStep = event?.step_index ? event.step_index - 2 : 0; // Approximate execution point

  const isDoNothing = event?.decision_result?.recommended_action === 'DO_NOTHING';
  const isNoSufficient = event?.decision_result?.recommendation_status === 'NO_SUFFICIENT_ACTION';

  // Verification derivation
  const verification = event?.outcome_verification;
  const verificationStatus = verification
    ? (verification as { status?: string })?.status ?? 'PENDING'
    : latestExecution
    ? latestExecution.verification_status ?? 'PENDING'
    : isDoNothing
    ? 'NO_ACTION_REQUIRED'
    : isNoSufficient
    ? 'NO_SUFFICIENT_ACTION'
    : 'NO_EXECUTION';

  const currentRisk = event?.current_risk_score ?? 0;
  const isWithinTarget = currentRisk <= 0.40;

  // Mismatch detection from reconsideration
  const hasMismatch = reconsideration?.contradictionDetected || false;
  const reconReason = reconsideration?.reason ?? '';

  return (
    <div className="space-y-10">
      {/* HEADING */}
      <section className="pb-6 border-b border-[#27272A]/60">
        <div className="font-mono text-xs text-[#71717A] tracking-widest uppercase mb-3 flex items-center gap-2">
          <span className="text-[#F0C808] font-semibold">STAGE 05</span>
          <span className="text-[#27272A]">·</span>
          <span>POST-EXECUTION OUTCOME VERIFICATION</span>
          {!isLive && <span className="text-[#F0C808] ml-2">[DEMO]</span>}
        </div>
        <h1 className="text-5xl font-bold tracking-tight text-white uppercase leading-none">
          VERIFICATION
        </h1>
        <p className="text-lg text-[#A1A1AA] mt-3 max-w-3xl leading-relaxed">
          Comparing the <strong className="text-white">observed post-execution state</strong> against the{' '}
          <strong className="text-white">expected outcome</strong> to determine whether the intervention achieved its target.
        </p>
      </section>

      {/* VERIFICATION STATUS */}
      <section className="flex flex-col md:flex-row md:items-end justify-between gap-8 py-6 border-y border-[#27272A]/60">
        <div className="space-y-3">
          <div className="font-mono text-xs text-[#71717A] uppercase tracking-widest font-medium">
            VERIFICATION VERDICT
          </div>
          <div className="flex items-baseline gap-4">
            <span className={`text-4xl font-bold tracking-tight font-mono ${
              verificationStatus === 'VERIFIED_SUCCESS' || verificationStatus === 'NO_ACTION_REQUIRED' ? 'text-green-400' :
              verificationStatus === 'VERIFIED_MISMATCH' || verificationStatus === 'NO_SUFFICIENT_ACTION' || hasMismatch ? 'text-[#F0C808]' :
              verificationStatus === 'INSUFFICIENT_EVIDENCE' ? 'text-[#A1A1AA]' :
              verificationStatus === 'NO_EXECUTION' ? 'text-[#71717A]' :
              'text-[#A1A1AA]'
            }`}>
              {verificationStatus === 'VERIFIED_SUCCESS'
                ? 'VERIFIED SUCCESS'
                : verificationStatus === 'NO_ACTION_REQUIRED'
                ? 'NO ACTION REQUIRED'
                : verificationStatus === 'NO_SUFFICIENT_ACTION'
                ? 'NO SUFFICIENT ACTION'
                : verificationStatus === 'VERIFIED_MISMATCH' || hasMismatch
                ? 'MISMATCH DETECTED'
                : verificationStatus === 'INSUFFICIENT_EVIDENCE'
                ? 'INSUFFICIENT EVIDENCE'
                : verificationStatus === 'NO_EXECUTION'
                ? 'AWAITING EXECUTION'
                : latestExecution
                ? (isWithinTarget ? 'WITHIN ENVELOPE' : 'EVALUATING WINDOWS')
                : 'AWAITING EXECUTION'}
            </span>
          </div>
          {isDoNothing && !latestExecution && (
            <p className="text-sm text-green-400/80 font-mono max-w-lg">
              Projected risk remains within safety envelope. System maintained passive monitoring.
            </p>
          )}
          {isNoSufficient && !latestExecution && (
            <p className="text-sm text-[#F0C808] font-mono max-w-lg">
              Available bounded interventions do not satisfy safety envelope. Escalated to human incident triage.
            </p>
          )}
          {hasMismatch && (
            <p className="text-sm text-[#F0C808] font-mono max-w-lg">
              {reconReason}
            </p>
          )}
        </div>

        <div className="flex items-center gap-8 font-mono shrink-0">
          <div>
            <div className="text-xs text-[#71717A] uppercase tracking-wider mb-1">CURRENT R(t)</div>
            <div className={`text-3xl font-bold tracking-tight ${isWithinTarget ? 'text-green-400' : 'text-[#F0C808]'}`}>
              {currentRisk.toFixed(2)}
            </div>
          </div>
          <div className="h-8 w-px bg-[#27272A]" />
          <div>
            <div className="text-xs text-[#71717A] uppercase tracking-wider mb-1">TARGET</div>
            <div className="text-3xl font-bold tracking-tight text-[#71717A]">≤ 0.40</div>
          </div>
          <div className="h-8 w-px bg-[#27272A]" />
          <div>
            <div className="text-xs text-[#71717A] uppercase tracking-wider mb-1">STATUS</div>
            <div className={`text-xs font-bold px-3.5 py-1 tracking-wider uppercase rounded-full ${
              isWithinTarget ? 'text-black bg-green-400 shadow-[0_0_10px_rgba(34,197,94,0.3)]' : 'text-black bg-[#F0C808] shadow-[0_0_10px_rgba(240,200,8,0.3)]'
            }`}>
              {isWithinTarget ? 'WITHIN TARGET' : 'EXCEEDS TARGET'}
            </div>
          </div>
        </div>
      </section>

      {/* VERIFICATION CHART */}
      <section className="space-y-3">
        <div className="flex items-center justify-between font-mono text-xs">
          <span className="text-[#A1A1AA] uppercase tracking-wider font-medium">
            OBSERVED RISK TRAJECTORY — PRE/POST EXECUTION
          </span>
          <div className="flex items-center gap-4 text-[#71717A]">
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 bg-white inline-block" />
              <span className="text-[#A1A1AA]">Pre-execution</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 bg-green-400 inline-block" />
              <span className="text-[#A1A1AA]">Post-execution</span>
            </div>
          </div>
        </div>
        {!event && connectionState === 'CONNECTING' ? (
          <AnalysisCardSkeleton type="chart" title="TRAJECTORY // OUTCOME VERIFICATION" ariaLabel="Loading verification chart..." />
        ) : (
          <VerificationChart events={eventHistory} executionStep={executionStep} />
        )}
      </section>

      {/* VERIFICATION WINDOWS */}
      <section className="border border-[#27272A]/60 bg-[#080808] p-8 rounded-3xl space-y-4 shadow-[0_4px_24px_rgba(0,0,0,0.4)]">
        <div className="flex items-center justify-between border-b border-[#27272A]/40 pb-3">
          <h2 className="text-xs font-mono uppercase tracking-widest text-[#71717A] font-bold">
            VERIFICATION EVALUATION WINDOWS
          </h2>
          <span className="text-xs font-mono text-[#71717A]">
            METHODOLOGY: POST-EXECUTION TRAJECTORY COMPARISON
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-sm">
          {[
            { label: '+10s POST-EXECUTION', offset: '+10s' },
            { label: '+20s POST-EXECUTION', offset: '+20s' },
            { label: '+30s POST-EXECUTION', offset: '+30s' },
          ].map(({ label, offset }) => {
            // Derive from future risk scores or historical events
            const postRisk = event?.future_risk_scores?.[offset as keyof typeof event.future_risk_scores];
            const withinTarget = postRisk !== undefined ? postRisk <= 0.40 : undefined;
            return (
              <div key={offset} className="border border-[#27272A]/40 bg-[#0a0a0a] p-5 rounded-2xl space-y-2">
                <div className="text-xs text-[#71717A] uppercase tracking-wider font-medium">{label}</div>
                <div className={`text-2xl font-bold tracking-tight ${
                  postRisk === undefined ? 'text-[#71717A]' : withinTarget ? 'text-green-400' : 'text-[#F0C808]'
                }`}>
                  {postRisk !== undefined ? postRisk.toFixed(2) : 'PENDING'}
                </div>
                <div className="text-xs text-[#71717A]">
                  {withinTarget === undefined ? 'Awaiting observation window' :
                   withinTarget ? '✓ Within target ceiling' : '⚠ Exceeds target ceiling'}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* EXECUTION RECORD */}
      {latestExecution && (
        <GlassPanel as="section" variant="default" className="border border-[#27272A]/60 p-8 rounded-3xl space-y-4 shadow-[0_4px_24px_rgba(0,0,0,0.4)]">
          <div className="text-xs font-mono uppercase tracking-widest text-[#71717A] font-bold border-b border-[#27272A]/40 pb-3">
            EXECUTION RECORD
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-sm">
            <div>
              <span className="text-xs text-[#71717A] block mb-0.5">EXECUTION ID</span>
              <span className="text-[#A1A1AA]">{latestExecution.execution_id}</span>
            </div>
            <div>
              <span className="text-xs text-[#71717A] block mb-0.5">ACTION ID</span>
              <span className="text-[#A1A1AA]">{latestExecution.action_id}</span>
            </div>
            <div>
              <span className="text-xs text-[#71717A] block mb-0.5">STATUS</span>
              <span className="text-white font-medium">{latestExecution.status}</span>
            </div>
            <div>
              <span className="text-xs text-[#71717A] block mb-0.5">VERIFIED</span>
              <span className={latestExecution.is_verified ? 'text-green-400' : 'text-[#F0C808]'}>
                {latestExecution.is_verified ? 'YES' : 'PENDING'}
              </span>
            </div>
          </div>
        </GlassPanel>
      )}

      {/* MISMATCH → RECONSIDERATION */}
      {hasMismatch && (
        <section className="border-2 border-[#F0C808]/30 bg-zinc-950/50 p-8 rounded-3xl space-y-3 shadow-[0_4px_30px_rgba(240,200,8,0.12)]">
          <div className="text-xs font-mono uppercase tracking-widest text-[#F0C808] font-bold flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#F0C808]" />
            RECONSIDERATION TRIGGERED
          </div>
          <p className="text-sm text-[#A1A1AA] font-mono max-w-2xl">
            {reconReason || 'Observed post-execution state diverges from expected outcome. System has triggered a reconsideration cycle.'}
          </p>
          <p className="text-xs text-[#71717A] font-mono">
            Reconsideration does NOT trigger autonomous response. The system returns to OBSERVE and begins a new assessment cycle.
          </p>
        </section>
      )}

      {/* PROGRESSIVE DISCLOSURE (CODEFRONTS GLZ-16) */}
      <GlassProgressiveDisclosure
        title="INSPECT VERIFICATION METHODOLOGY & OUTCOME ATTRIBUTION"
        badge={verificationStatus}
      >
        <div className="font-mono text-xs text-[#71717A] space-y-3">
          <div>Verification Method: <span className="text-[#A1A1AA]">Post-execution trajectory comparison against target ceiling</span></div>
          <div>Verdict Taxonomy: <span className="text-[#A1A1AA]">VERIFIED_SUCCESS | VERIFIED_MISMATCH | INSUFFICIENT_EVIDENCE</span></div>
          <div>Mismatch triggers: <span className="text-[#A1A1AA]">Reconsideration cycle (not autonomous response)</span></div>
          <div>Window Size: <span className="text-[#A1A1AA]">+10s, +20s, +30s post-execution observation windows</span></div>
          {event?.outcome_verification && (
            <div className="mt-2 pt-2 border-t border-[#27272A]/30">
              <div className="text-[#71717A] uppercase mb-1">RAW VERIFICATION DATA</div>
              <pre className="text-[#A1A1AA] text-[10px] whitespace-pre-wrap">
                {JSON.stringify(event.outcome_verification, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </GlassProgressiveDisclosure>
    </div>
  );
};
