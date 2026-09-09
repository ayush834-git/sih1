import React, { useState, useCallback } from 'react';
import { useRuntimeStore } from '../store/useRuntimeStore';
import { apiClient } from '../lib/api';
import { useControlCenterStore } from '../store/useControlCenterStore';
import type { ResponseExecutionResponse } from '../types/runtime';
import { TraceText } from '../components/common/EncasedHover';
import { ApprovalFormSkeleton } from '../components/common/ShimmerSkeletons';
import { ConicBorderPanel } from '../components/common/ConicBorderPanel';
import { GlassPanel } from '../components/common/GlassPanel';
import { GlassProgressiveDisclosure } from '../components/common/GlassProgressiveDisclosure';

/**
 * Stage 04: APPROVE — "Should I approve this action?"
 * Mandatory human approval gate before any defensive execution.
 * Connected to apiClient.executeResponseAction() for real dispatch.
 */

type GateState = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXECUTING' | 'EXECUTED' | 'ERROR';

export const HumanApprovalPage: React.FC = () => {
  const { snapshot, connectionState } = useRuntimeStore();
  const { currentUser } = useControlCenterStore();
  const [gateState, setGateState] = useState<GateState>('PENDING');
  const [executionResult, setExecutionResult] = useState<ResponseExecutionResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [approvalReason, setApprovalReason] = useState('');

  const event = snapshot.event;
  const isLive = connectionState === 'CONNECTED';
  const authority = event?.authority_policy;
  const requiresHuman = event?.requires_human ?? true;
  const recommendedActions = event?.recommended_actions ?? [];
  const msiAction = recommendedActions[0];
  const currentRisk = event?.current_risk_score ?? 0;
  const futureRisks = event?.future_risk_scores ?? {};
  const t30 = futureRisks['+30s'] ?? 0;

  // Evidence summary for the approval gate
  const evidenceSummary = {
    observedRisk: currentRisk,
    forecastPeak: Math.max(futureRisks['+10s'] ?? 0, futureRisks['+20s'] ?? 0, t30),
    stage: event?.primary_stage ?? 'Unknown',
    confidence: event?.stage_confidence ?? 0,
    activeSignatures: event?.active_signatures ?? [],
    trustLevel: event?.trust_level ?? 'UNKNOWN',
  };

  const handleApprove = useCallback(async () => {
    if (!msiAction || !event || !authority) {
      setErrorMsg('Cannot approve: missing action context, event data, or authority binding.');
      return;
    }
    if (msiAction.action_type === 'NO_SUFFICIENT_ACTION') {
      setErrorMsg('Cannot dispatch automated response: safety boundary exceeded. Manual incident response escalation required.');
      return;
    }
    if (msiAction.action_type === 'DO_NOTHING') {
      setGateState('APPROVED');
      return;
    }
    setGateState('EXECUTING');
    setErrorMsg(null);
    try {
      const result = await apiClient.executeResponseAction({
        action_type: msiAction.action_type,
        action_class: 'EXECUTE_REVERSIBLE_ACTION',
        target_node_id: msiAction.target,
        authority_decision_id: authority.decision_id,
        evidence_window_id: event.event_id || event.security_explanation?.window_id,
        expected_effect: msiAction.expected_impact ?? 'Risk reduction to within target ceiling',
        approval: {
          approved: true,
          approver_reference: currentUser?.name ?? 'OPERATOR_01',
          approval_reason: approvalReason || 'Approved via Stage 04 Human Gate',
          authority_decision_id: authority.decision_id,
          evidence_window_id: event.event_id || event.security_explanation?.window_id,
        },
      });
      setExecutionResult(result);
      setGateState('EXECUTED');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
      setGateState('ERROR');
    }
  }, [msiAction, event, authority, approvalReason, currentUser]);

  const handleReject = useCallback(() => {
    setGateState('REJECTED');
  }, []);

  if (!event && connectionState === 'CONNECTING') {
    return (
      <div className="space-y-10">
        {/* HEADER */}
        <section className="pb-6 border-b border-[#27272A]/60">
          <div className="font-mono text-xs text-[#71717A] tracking-widest uppercase mb-3 flex items-center gap-2">
            <span className="text-[#F0C808] font-semibold">STAGE 04</span>
            <span className="text-[#27272A]">·</span>
            <span>HUMAN APPROVAL GATE — MANDATORY</span>
          </div>
          <h1 className="text-5xl font-bold tracking-tight text-white uppercase leading-none">
            AUTHORIZATION REQUIRED
          </h1>
          <p className="text-lg text-[#A1A1AA] mt-3 max-w-3xl leading-relaxed">
            The system has identified a recommended intervention but{' '}
            <strong className="text-white">cannot execute autonomously</strong>. Human evaluation
            and explicit approval is required before any defensive action is dispatched.
          </p>
        </section>

        {/* SKELETON LOADING STATE (SSC-10) */}
        <ApprovalFormSkeleton ariaLabel="Loading approval request..." />
      </div>
    );
  }

  return (
    <div className="space-y-10">
      {/* HEADER */}
      <section className="pb-6 border-b border-[#27272A]/60">
        <div className="font-mono text-xs text-[#71717A] tracking-widest uppercase mb-3 flex items-center gap-2">
          <span className="text-[#F0C808] font-semibold">STAGE 04</span>
          <span className="text-[#27272A]">·</span>
          <span>HUMAN APPROVAL GATE — MANDATORY</span>
          {!isLive && <span className="text-[#F0C808] ml-2">[DEMO]</span>}
        </div>
        <h1 className="text-5xl font-bold tracking-tight text-white uppercase leading-none">
          AUTHORIZATION REQUIRED
        </h1>
        <p className="text-lg text-[#A1A1AA] mt-3 max-w-3xl leading-relaxed">
          The system has identified a recommended intervention but{' '}
          <strong className="text-white">cannot execute autonomously</strong>. Human evaluation
          and explicit approval is required before any defensive action is dispatched.
        </p>
      </section>

      {/* STATUS BADGE */}
      <div className="flex items-center gap-6 font-mono text-sm">
        <div className={`flex items-center gap-2.5 px-4 py-2 rounded-full border ${
          gateState === 'PENDING' ? 'border-[#F0C808] text-[#F0C808] bg-[#F0C808]/5' :
          gateState === 'APPROVED' || gateState === 'EXECUTED' ? 'border-green-500 text-green-400 bg-green-500/5' :
          gateState === 'REJECTED' ? 'border-[#71717A] text-[#71717A] bg-zinc-800/40' :
          gateState === 'ERROR' ? 'border-red-500 text-red-400 bg-red-500/5' :
          'border-[#F0C808] text-[#F0C808] bg-[#F0C808]/5'
        }`}>
          <span className={`w-2 h-2 rounded-full ${
            gateState === 'PENDING' ? 'bg-[#F0C808] animate-pulse' :
            gateState === 'APPROVED' || gateState === 'EXECUTED' ? 'bg-green-400' :
            gateState === 'REJECTED' ? 'bg-[#71717A]' :
            gateState === 'EXECUTING' ? 'bg-[#F0C808] animate-pulse' :
            'bg-red-400'
          }`} />
          <span className="uppercase tracking-widest text-xs font-semibold">
            {gateState === 'PENDING' ? 'AWAITING HUMAN APPROVAL' :
             gateState === 'APPROVED' ? 'APPROVAL GRANTED' :
             gateState === 'EXECUTING' ? 'DISPATCHING ACTION...' :
             gateState === 'EXECUTED' ? 'ACTION DISPATCHED' :
             gateState === 'REJECTED' ? 'INTERVENTION REJECTED' :
             'EXECUTION ERROR'}
          </span>
        </div>
        {authority && (
          <span className="text-xs text-[#71717A]">
            AUTHORITY: <span className="text-[#A1A1AA] font-medium">{authority.authority_level}</span>
            <span className="text-[#27272A] mx-2">·</span>
            DECISION: <span className="text-[#A1A1AA] font-medium">{authority.decision_id}</span>
          </span>
        )}
      </div>

      {/* PROPOSED ACTION CARD */}
      <GlassPanel as="section" variant="default" className="border border-[#27272A]/70 p-8 rounded-3xl shadow-[0_4px_24px_rgba(0,0,0,0.4)]">
        <div className="flex items-center justify-between border-b border-[#27272A]/40 pb-4 mb-6">
          <h2 className="text-xs font-mono uppercase tracking-widest text-[#71717A] font-bold">
            PROPOSED INTERVENTION FOR APPROVAL
          </h2>
          <span className="text-xs font-mono text-[#71717A]">
            REQUIRES HUMAN: <span className="text-[#F0C808] font-semibold">{requiresHuman ? 'YES' : 'NO'}</span>
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Action Details */}
          <div className="space-y-4 lg:col-span-2">
            <div className="flex items-baseline gap-4">
              <span className="text-3xl font-bold text-white tracking-tight font-mono">
                {msiAction?.action_type ?? 'NO ACTION PROPOSED'}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-4 font-mono text-sm">
              <div>
                <span className="text-xs text-[#71717A] uppercase tracking-wider block mb-0.5">TARGET</span>
                <span className="text-white font-medium">{msiAction?.target ?? '—'}</span>
              </div>
              <div>
                <span className="text-xs text-[#71717A] uppercase tracking-wider block mb-0.5">URGENCY</span>
                <span className="text-[#F0C808] font-medium">{msiAction?.urgency ?? '—'}</span>
              </div>
              <div>
                <span className="text-xs text-[#71717A] uppercase tracking-wider block mb-0.5">EXPECTED IMPACT</span>
                <span className="text-[#A1A1AA]">{msiAction?.expected_impact ?? 'Risk reduction within target ceiling'}</span>
              </div>
              <div>
                <span className="text-xs text-[#71717A] uppercase tracking-wider block mb-0.5">REVERSIBILITY</span>
                <span className="text-[#A1A1AA]">{event?.is_reversible ? 'REVERSIBLE (bounded TTL)' : 'NON-REVERSIBLE'}</span>
              </div>
            </div>
          </div>

          {/* Contextual Evidence */}
          <div className="border-t lg:border-t-0 lg:border-l border-[#27272A]/40 pt-4 lg:pt-0 lg:pl-8 font-mono text-sm space-y-3">
            <div className="text-xs text-[#71717A] uppercase tracking-wider font-bold mb-3">SUPPORTING EVIDENCE</div>
            <div className="flex justify-between">
              <span className="text-[#71717A]">Observed Risk</span>
              <span className="text-white font-medium">{evidenceSummary.observedRisk.toFixed(2)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#71717A]">Forecast Peak</span>
              <span className="text-[#F0C808] font-medium">{evidenceSummary.forecastPeak.toFixed(2)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#71717A]">Stage</span>
              <span className="text-[#A1A1AA]">{evidenceSummary.stage}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#71717A]">Confidence</span>
              <span className="text-[#A1A1AA]">{(evidenceSummary.confidence * 100).toFixed(0)}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#71717A]">Trust</span>
              <span className="text-[#A1A1AA]">{evidenceSummary.trustLevel}</span>
            </div>
            {evidenceSummary.activeSignatures.length > 0 && (
              <div className="pt-2 border-t border-[#27272A]/30">
                <span className="text-[10px] text-[#71717A] uppercase tracking-wider block mb-1">ACTIVE SIGNATURES</span>
                <div className="flex flex-wrap gap-1.5">
                  {evidenceSummary.activeSignatures.slice(0, 3).map((sig) => (
                    <span key={sig} className="px-3 py-0.5 bg-[#18181b] text-[#A1A1AA] text-xs rounded-full">{sig}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </GlassPanel>

      {/* APPROVAL CONTROLS */}
      {gateState === 'PENDING' && (
        <ConicBorderPanel
          as="section"
          variant="approval"
          animated={gateState === 'PENDING'}
          className="bg-zinc-950/50 p-8 rounded-3xl space-y-6 shadow-[0_4px_30px_rgba(240,200,8,0.12)]"
        >
          <div className="text-xs font-mono uppercase tracking-widest text-[#F0C808] font-bold">
            OPERATOR ACTION REQUIRED
          </div>

          <div className="space-y-3">
            <label className="text-xs font-mono text-[#71717A] uppercase tracking-wider block">
              APPROVAL JUSTIFICATION (OPTIONAL)
            </label>
            <textarea
              className="w-full bg-[#080808] border border-[#27272A] text-white font-mono text-sm p-4 rounded-2xl focus:border-[#F0C808] focus:outline-none resize-none"
              rows={2}
              placeholder="Provide justification for audit trail..."
              value={approvalReason}
              onChange={(e) => setApprovalReason(e.target.value)}
            />
          </div>

          <div className="flex flex-wrap items-center gap-4">
            {msiAction?.action_type === 'NO_SUFFICIENT_ACTION' ? (
              <button
                disabled
                className="px-8 py-3.5 bg-[#27272A] text-[#71717A] font-mono font-bold text-sm tracking-widest uppercase cursor-not-allowed flex items-center gap-3 rounded-full"
                type="button"
              >
                <span>AUTOMATED DISPATCH BLOCKED // SAFETY BOUNDARY EXCEEDED</span>
              </button>
            ) : msiAction?.action_type === 'DO_NOTHING' ? (
              <button
                onClick={handleApprove}
                data-cursor="critical"
                className="px-8 py-3.5 bg-green-500 hover:bg-green-400 text-black font-mono font-bold text-sm tracking-widest uppercase transition-all focus:outline-none flex items-center gap-3 rounded-full shadow-[0_0_15px_rgba(34,197,94,0.3)] hover:shadow-[0_0_20px_rgba(34,197,94,0.5)]"
                type="button"
              >
                <span>CONFIRM PASSIVE MONITORING (RESTRAINT)</span>
                <span className="font-bold">✓</span>
              </button>
            ) : (
              <button
                onClick={handleApprove}
                data-cursor="critical"
                className="px-8 py-3.5 bg-[#F0C808] hover:bg-[#FFE14C] text-black font-mono font-bold text-sm tracking-widest uppercase transition-all focus:outline-none flex items-center gap-3 rounded-full shadow-[0_0_18px_rgba(240,200,8,0.35)] hover:shadow-[0_0_25px_rgba(240,200,8,0.55)]"
                type="button"
              >
                <span>APPROVE & DISPATCH ACTION</span>
                <span className="font-bold">→</span>
              </button>
            )}
            <button
              onClick={handleReject}
              data-cursor="critical"
              className="px-7 py-3.5 border border-[#27272A] hover:border-[#71717A] text-[#A1A1AA] hover:text-white font-mono text-sm tracking-widest uppercase transition-colors focus:outline-none rounded-full bg-[#080808]"
              type="button"
            >
              REJECT INTERVENTION
            </button>
          </div>
        </ConicBorderPanel>
      )}

      {/* REJECTED STATE */}
      {gateState === 'REJECTED' && (
        <section className="border border-[#27272A] bg-[#080808] p-8 rounded-3xl space-y-4 shadow-[0_4px_24px_rgba(0,0,0,0.4)]">
          <div className="text-xs font-mono uppercase tracking-widest text-[#71717A] font-bold">
            INTERVENTION REJECTED BY OPERATOR
          </div>
          <p className="text-sm text-[#A1A1AA]">
            The proposed intervention has been rejected. The system will continue monitoring in OBSERVE mode.
            No defensive action has been dispatched. This decision is logged in the audit trail.
          </p>
          <TraceText
            onClick={() => setGateState('PENDING')}
            variant="surface"
            className="px-5 py-2.5 text-xs font-mono text-[#A1A1AA]"
          >
            <span>RECONSIDER</span>
          </TraceText>
        </section>
      )}

      {/* EXECUTED STATE */}
      {(gateState === 'EXECUTED' || gateState === 'EXECUTING') && (
        <section className="border border-green-500/30 bg-green-950/10 p-8 rounded-3xl space-y-4 shadow-[0_4px_30px_rgba(34,197,94,0.15)]">
          <div className="text-xs font-mono uppercase tracking-widest text-green-400 font-bold flex items-center gap-2">
            {gateState === 'EXECUTING' ? (
              <>
                <span className="w-2 h-2 rounded-full bg-[#F0C808] animate-pulse" />
                DISPATCHING...
              </>
            ) : (
              <>
                <span className="w-2 h-2 rounded-full bg-green-400" />
                ACTION DISPATCHED SUCCESSFULLY
              </>
            )}
          </div>
          {executionResult && (
            <div className="font-mono text-sm text-[#A1A1AA] space-y-1">
              <div>Execution ID: <span className="text-white">{executionResult.execution_id}</span></div>
              <div>Status: <span className="text-green-400">{executionResult.status}</span></div>
              <div>Message: <span className="text-white">{executionResult.message}</span></div>
            </div>
          )}
          <p className="text-sm text-[#A1A1AA]">
            Proceed to <strong className="text-white">Stage 05: VERIFY</strong> to evaluate the intervention's effect.
          </p>
        </section>
      )}

      {/* ERROR STATE */}
      {gateState === 'ERROR' && errorMsg && (
        <section className="border border-red-500/30 bg-red-950/10 p-8 rounded-3xl space-y-4">
          <div className="text-xs font-mono uppercase tracking-widest text-red-400 font-bold">
            EXECUTION ERROR
          </div>
          <p className="text-sm text-red-300 font-mono">{errorMsg}</p>
          <TraceText
            onClick={() => setGateState('PENDING')}
            variant="surface"
            className="px-5 py-2.5 text-xs font-mono text-red-400"
          >
            <span>RETRY</span>
          </TraceText>
        </section>
      )}

      {/* AUTHORITY POLICY (CODEFRONTS GLZ-16) */}
      {authority && (
        <GlassProgressiveDisclosure
          title="INSPECT AUTHORITY POLICY BINDING & DECISION PROVENANCE"
          badge={authority.authority_level}
        >
          <div className="font-mono text-xs text-[#71717A] space-y-2">
            <div>Decision ID: <span className="text-[#A1A1AA]">{authority.decision_id}</span></div>
            <div>Authority Level: <span className="text-white font-semibold">{authority.authority_level}</span></div>
            <div>Policy Version: <span className="text-[#A1A1AA]">{authority.policy_version}</span></div>
            <div>Human Approval Required: <span className="text-[#F0C808] font-bold">{authority.human_approval_required ? 'YES' : 'NO'}</span></div>
            <div>Explanation: <span className="text-[#A1A1AA]">{authority.explanation}</span></div>
            <div>Provenance Hash: <span className="text-[#A1A1AA]">{authority.provenance_hash}</span></div>
            <div>Permitted Actions: <span className="text-[#A1A1AA]">{authority.permitted_action_classes.join(', ') || '—'}</span></div>
            <div>Blocked Actions: <span className="text-[#A1A1AA]">{authority.blocked_action_classes.join(', ') || '—'}</span></div>
          </div>
        </GlassProgressiveDisclosure>
      )}
    </div>
  );
};
