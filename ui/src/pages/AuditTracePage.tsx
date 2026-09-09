import React, { useState, useEffect } from 'react';
import { useRuntimeStore } from '../store/useRuntimeStore';
import { useControlCenterStore } from '../store/useControlCenterStore';
import { apiClient } from '../lib/api';
import type { ResponseExecutionResponse } from '../types/runtime';
import {
  SearchTraceSkeleton,
  AnalysisCardSkeleton,
  ApprovalFormSkeleton,
} from '../components/common/ShimmerSkeletons';
import { GlassPanel } from '../components/common/GlassPanel';
import { GlassKpiCountUp } from '../components/common/GlassKpiCountUp';
import { GlassProgressiveDisclosure } from '../components/common/GlassProgressiveDisclosure';
import { AuditArtifactCard } from '../components/common/AuditArtifactCard';

/**
 * Stage 06: TRACE — "What actually happened?"
 * Complete chronological audit trail, provenance ledger, and immutable record.
 */

export const AuditTracePage: React.FC = () => {
  const { snapshot, eventHistory, connectionState, demoStatus } = useRuntimeStore();
  const { auditLogs } = useControlCenterStore();
  const [responseHistory, setResponseHistory] = useState<ResponseExecutionResponse[]>([]);
  const [activeTab, setActiveTab] = useState<'timeline' | 'execution' | 'audit'>('timeline');
  const [provenance, setProvenance] = useState<Record<string, unknown> | null>(null);
  const [loadingHistory, setLoadingHistory] = useState<boolean>(true);

  const event = snapshot.event;
  const isLive = connectionState === 'CONNECTED';

  // Fetch data on mount
  useEffect(() => {
    let mounted = true;
    setLoadingHistory(true);
    Promise.all([
      apiClient.getResponseHistory().then((res) => { if (mounted) setResponseHistory(res); }).catch(() => {}),
      apiClient.getLiveProvenance().then((res) => { if (mounted) setProvenance(res); }).catch(() => {}),
    ]).finally(() => {
      if (mounted) setLoadingHistory(false);
    });
    return () => { mounted = false; };
  }, [event?.step_index]);

  // Summary statistics
  const totalEvents = eventHistory.length;
  const totalExecutions = responseHistory.length;
  const totalAuditEntries = auditLogs.length;
  const verifiedCount = responseHistory.filter((r) => r.is_verified).length;
  const mismatchCount = responseHistory.filter((r) => r.verification_status === 'VERIFIED_MISMATCH').length;

  const tabs = [
    { id: 'timeline' as const, label: 'EVENT TIMELINE', count: totalEvents },
    { id: 'execution' as const, label: 'EXECUTION RECORDS', count: totalExecutions },
    { id: 'audit' as const, label: 'SYSTEM AUDIT LOG', count: totalAuditEntries },
  ];

  return (
    <div className="space-y-10">
      {/* HEADING */}
      <section className="pb-6 border-b border-[#27272A]/60">
        <div className="font-mono text-xs text-[#71717A] tracking-widest uppercase mb-3 flex items-center gap-2">
          <span className="text-[#F0C808] font-semibold">STAGE 06</span>
          <span className="text-[#27272A]">·</span>
          <span>IMMUTABLE AUDIT TRAIL & DECISION PROVENANCE</span>
          {!isLive && <span className="text-[#F0C808] ml-2">[DEMO]</span>}
        </div>
        <h1 className="text-5xl font-bold tracking-tight text-white uppercase leading-none">
          AUDIT & TRACE
        </h1>
        <p className="text-lg text-[#A1A1AA] mt-3 max-w-3xl leading-relaxed">
          Complete chronological record of every observation, decision, execution, and verification
          performed during this incident lifecycle. All records are immutable and hash-verifiable.
        </p>
      </section>

      {/* SUMMARY METRICS (CODEFRONTS GLZ-11 & GLZ-23) */}
      <GlassPanel
        as="section"
        variant="default"
        className="p-6 border border-[#27272A]/70 rounded-3xl grid grid-cols-2 md:grid-cols-5 gap-6 font-mono shadow-[0_4px_24px_rgba(0,0,0,0.4)]"
      >
        {[
          { label: 'TOTAL EVENTS', value: totalEvents, color: 'text-white' },
          { label: 'EXECUTIONS', value: totalExecutions, color: 'text-white' },
          { label: 'VERIFIED', value: verifiedCount, color: 'text-green-400' },
          { label: 'MISMATCHES', value: mismatchCount, color: mismatchCount > 0 ? 'text-[#F0C808]' : 'text-[#71717A]' },
          { label: 'AUDIT ENTRIES', value: totalAuditEntries, color: 'text-white' },
        ].map(({ label, value, color }) => (
          <div key={label}>
            <div className="text-xs text-[#71717A] uppercase tracking-wider mb-1">{label}</div>
            <div className={`text-3xl font-bold tracking-tight ${color}`}>
              <GlassKpiCountUp value={value} />
            </div>
          </div>
        ))}
      </GlassPanel>

      {/* TAB NAVIGATION PILL BAR */}
      <div className="flex items-center gap-1.5 p-1.5 bg-[#080808] border border-[#27272A]/60 rounded-full w-fit">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`px-5 py-2 font-mono text-xs uppercase tracking-widest transition-all rounded-full ${
              activeTab === tab.id
                ? 'bg-[#F0C808] text-black font-bold shadow-[0_0_12px_rgba(240,200,8,0.35)]'
                : 'text-[#71717A] hover:text-white hover:bg-[#141414]'
            }`}
            onClick={() => setActiveTab(tab.id)}
            type="button"
          >
            {tab.label}
            <span className={`ml-1.5 text-[11px] ${activeTab === tab.id ? 'text-black/70 font-semibold' : 'text-[#52525B]'}`}>({tab.count})</span>
          </button>
        ))}
      </div>

      {/* TAB CONTENT */}
      {activeTab === 'timeline' && (
        <section className="space-y-1">
          {eventHistory.length === 0 && connectionState === 'CONNECTING' ? (
            <SearchTraceSkeleton count={4} ariaLabel="Loading audit event timeline records..." />
          ) : (
            <div className="border border-[#27272A]/60 bg-[#080808] rounded-3xl overflow-hidden shadow-[0_4px_24px_rgba(0,0,0,0.4)]">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="text-[#71717A] text-[10px] uppercase tracking-wider border-b border-[#27272A]/60">
                    <th className="py-3 px-4 font-medium">STEP</th>
                    <th className="py-3 px-4 font-medium">TIME</th>
                    <th className="py-3 px-4 font-medium">STAGE</th>
                    <th className="py-3 px-4 font-medium">RISK</th>
                    <th className="py-3 px-4 font-medium">TRUST</th>
                    <th className="py-3 px-4 font-medium">PRIORITY</th>
                    <th className="py-3 px-4 font-medium">STRATEGY</th>
                    <th className="py-3 px-4 font-medium text-right">EVENT ID</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#18181b]/60">
                  {eventHistory.slice().reverse().map((evt) => (
                    <tr key={evt.event_id} className="hover:bg-zinc-900/30 transition-colors">
                      <td className="py-2.5 px-4 text-white font-medium">
                        {evt.step_index}
                      </td>
                      <td className="py-2.5 px-4 text-[#A1A1AA]">
                        {evt.logical_time_str}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`px-3 py-0.5 text-[10px] uppercase tracking-wider font-medium rounded-full ${
                          evt.primary_stage === 'Reconnaissance' ? 'text-[#F0C808] bg-[#F0C808]/10 border border-[#F0C808]/30' :
                          evt.primary_stage === 'Unknown / Benign' ? 'text-[#71717A] bg-zinc-800/40 border border-zinc-700/40' :
                          'text-[#A1A1AA] bg-zinc-800/40 border border-zinc-700/40'
                        }`}>
                          {evt.primary_stage}
                        </span>
                      </td>
                      <td className={`py-2.5 px-4 font-medium ${
                        evt.current_risk_score > 0.6 ? 'text-[#F0C808]' :
                        evt.current_risk_score > 0.4 ? 'text-[#A1A1AA]' :
                        'text-[#71717A]'
                      }`}>
                        {evt.current_risk_score.toFixed(2)}
                      </td>
                      <td className="py-2.5 px-4 text-[#A1A1AA]">
                        {evt.composite_trust.toFixed(2)}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`px-2.5 py-0.5 text-[10px] uppercase tracking-wider font-semibold rounded-full ${
                          evt.priority_level === 'CRITICAL' ? 'text-[#F0C808] bg-[#F0C808]/10 border border-[#F0C808]/30' :
                          evt.priority_level === 'HIGH' ? 'text-[#A1A1AA] bg-zinc-800/40' :
                          'text-[#71717A]'
                        }`}>
                          {evt.priority_level}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-[#71717A]">
                        {evt.recommended_strategy}
                      </td>
                      <td className="py-2.5 px-4 text-right text-[#52525B] text-[10px]">
                        {evt.event_id.slice(0, 12)}…
                      </td>
                    </tr>
                  ))}
                  {eventHistory.length === 0 && (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-[#71717A]">
                        No events recorded. Start a simulation to generate telemetry.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {activeTab === 'execution' && (
        <section className="space-y-4">
          {loadingHistory && responseHistory.length === 0 ? (
            <SearchTraceSkeleton count={3} ariaLabel="Loading response execution records..." />
          ) : responseHistory.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {responseHistory.map((rec) => (
                <AuditArtifactCard key={rec.execution_id} record={rec} />
              ))}
            </div>
          ) : (
            <GlassPanel variant="default" className="border border-[#27272A]/60 p-12 text-center text-[#71717A] font-mono text-xs">
              No execution records. Execute an intervention in Stage 04 to generate immutable records.
            </GlassPanel>
          )}
        </section>
      )}

      {activeTab === 'audit' && (
        <section className="space-y-1">
          {auditLogs.length === 0 && connectionState === 'CONNECTING' ? (
            <SearchTraceSkeleton count={3} ariaLabel="Loading system audit log..." />
          ) : (
            <div className="border border-[#27272A]/60 bg-[#080808] rounded-3xl overflow-hidden shadow-[0_4px_24px_rgba(0,0,0,0.4)]">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="text-[#71717A] text-[10px] uppercase tracking-wider border-b border-[#27272A]/60">
                  <th className="py-3 px-4 font-medium">TIMESTAMP</th>
                  <th className="py-3 px-4 font-medium">ACTOR</th>
                  <th className="py-3 px-4 font-medium">ACTION</th>
                  <th className="py-3 px-4 font-medium">OBJECT</th>
                  <th className="py-3 px-4 font-medium">RESULT</th>
                  <th className="py-3 px-4 font-medium text-right">DETAIL</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#18181b]/60">
                {auditLogs.slice(0, 50).map((log) => (
                  <tr key={log.id} className="hover:bg-zinc-900/30 transition-colors">
                    <td className="py-2.5 px-4 text-[#A1A1AA] whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 text-white font-medium">
                      {log.actor}
                    </td>
                    <td className="py-2.5 px-4 text-[#A1A1AA]">
                      {log.action}
                    </td>
                    <td className="py-2.5 px-4 text-[#71717A]">
                      {log.object}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={`px-3 py-0.5 text-[10px] uppercase tracking-wider font-semibold rounded-full ${
                        log.result === 'SUCCESS' ? 'text-green-400 bg-green-400/10 border border-green-400/30' :
                        log.result?.includes('FATAL') ? 'text-red-400 bg-red-400/10 border border-red-400/30' :
                        'text-[#F0C808] bg-[#F0C808]/10 border border-[#F0C808]/30'
                      }`}>
                        {log.result}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right text-[#52525B] max-w-xs truncate">
                      {log.detail}
                    </td>
                  </tr>
                ))}
                {auditLogs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-[#71717A]">
                      No audit log entries recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          )}
        </section>
      )}

      {/* PROVENANCE (CODEFRONTS GLZ-16) */}
      <GlassProgressiveDisclosure
        title="INSPECT SESSION PROVENANCE & RUN MANIFEST"
        badge={demoStatus.scenario || 'RUN MANIFEST'}
      >
        <div className="font-mono text-xs text-[#71717A] space-y-3">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-xs text-[#71717A] block mb-0.5">SESSION ID</span>
              <span className="text-[#A1A1AA] font-semibold">{demoStatus.session_id}</span>
            </div>
            <div>
              <span className="text-xs text-[#71717A] block mb-0.5">SCENARIO</span>
              <span className="text-[#A1A1AA]">{demoStatus.scenario}</span>
            </div>
            <div>
              <span className="text-xs text-[#71717A] block mb-0.5">STATUS</span>
              <span className="text-white font-bold">{demoStatus.status}</span>
            </div>
            <div>
              <span className="text-xs text-[#71717A] block mb-0.5">TOTAL STEPS</span>
              <span className="text-[#A1A1AA]">{demoStatus.total_steps}</span>
            </div>
          </div>
          {provenance && (
            <div className="mt-4 pt-3 border-t border-[#27272A]/30">
              <div className="text-[#71717A] uppercase mb-2 font-bold">LIVE RUN PROVENANCE</div>
              <pre className="text-[#A1A1AA] text-[10px] whitespace-pre-wrap max-h-48 overflow-y-auto bg-[#000001] p-4 rounded-xl border border-[#27272A]/30">
                {JSON.stringify(provenance, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </GlassProgressiveDisclosure>

      {/* SHIMMER SKELETON SPECIFICATION PANEL (CODEFRONTS GLZ-16) */}
      <GlassProgressiveDisclosure
        title="INSPECT CODEFRONTS SHIMMER SKELETON PRIMITIVES (SSC-07, SSC-09, SSC-10)"
        badge="LOADING PRIMITIVES"
      >
        <div className="font-mono text-xs text-[#71717A] space-y-6">
          <div className="space-y-2">
            <div className="text-[#F0C808] text-xs font-semibold uppercase tracking-wider">
              1. SSC-07 — SEARCH RESULT / TRACE LIST ITEM SKELETON
            </div>
            <p className="text-[#A1A1AA] text-xs leading-relaxed max-w-2xl font-sans">
              Asymmetric spacing between title and supporting detail lines with staggered 1.8s shimmer sweep.
            </p>
            <SearchTraceSkeleton count={2} ariaLabel="Preview of SSC-07 trace skeleton" />
          </div>

          <div className="space-y-2 pt-4 border-t border-white/5">
            <div className="text-[#F0C808] text-xs font-semibold uppercase tracking-wider">
              2. SSC-09 — CONTENT / ANALYSIS CARD & CHART SKELETON
            </div>
            <p className="text-[#A1A1AA] text-xs leading-relaxed max-w-2xl font-sans">
              Preserves 400px–450px chart geometry with axis and threshold placeholders. Zero fake curves.
            </p>
            <AnalysisCardSkeleton type="chart" title="PREVIEW // AR(5) FORECAST CHART SKELETON" />
          </div>

          <div className="space-y-2 pt-4 border-t border-white/5">
            <div className="text-[#F0C808] text-xs font-semibold uppercase tracking-wider">
              3. SSC-10 — FORM INPUT / APPROVAL GATE PLACEHOLDER SKELETON
            </div>
            <p className="text-[#A1A1AA] text-xs leading-relaxed max-w-2xl font-sans">
              Structured input silhouettes with explicit &quot;LOADING APPROVAL REQUEST&quot; state. Never implies authorization.
            </p>
            <ApprovalFormSkeleton ariaLabel="Preview of SSC-10 approval form skeleton" />
          </div>
        </div>
      </GlassProgressiveDisclosure>
    </div>
  );
};
