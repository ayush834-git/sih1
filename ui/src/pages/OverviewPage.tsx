import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useControlCenterStore } from '../store/useControlCenterStore';
import { useRuntimeStore } from '../store/useRuntimeStore';
import { BadgeDelta } from '../components/ui/badge-delta';
import type { GraphNodeData } from '../types/controlCenter';
import { OVERVIEW_GRAPH_NODES } from '../data/mockData';
import { apiClient } from '../lib/api';
import type { ResponseExecutionResponse } from '../types/runtime';

export const OverviewPage: React.FC = () => {
  const { cases, activeCase, setActiveCaseId, isolateSubject, isLiveSync, toggleLiveSync } =
    useControlCenterStore();
  const { snapshot, eventHistory, demoStatus, connectionState } = useRuntimeStore();
  const [selectedNodeId, setSelectedNodeId] = useState<string>('ov-3');
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [isolated, setIsolated] = useState<boolean>(false);
  const [isApprovalModalOpen, setIsApprovalModalOpen] = useState<boolean>(false);
  const [approverRef, setApproverRef] = useState<string>('ANALYST_01');
  const [approvalReason, setApprovalReason] = useState<string>(
    'Mitigate unauthorized ingress sweep on Gateway Node 4'
  );
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [executionResult, setExecutionResult] = useState<ResponseExecutionResponse | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const navigate = useNavigate();

  const liveEvent = snapshot.event;
  const isIdle = demoStatus.status === 'IDLE' && !liveEvent;

  const currentConfidencePct = liveEvent
    ? Math.round(liveEvent.stage_confidence * 100)
    : isIdle
    ? 85
    : activeCase.attributionConfidence;

  const currentTrustPct = liveEvent
    ? Math.round(liveEvent.composite_trust * 100)
    : isIdle
    ? 85
    : 85;

  const handleExecuteApproval = async (approved: boolean) => {
    setIsExecuting(true);
    setExecutionError(null);
    try {
      const decisionId = liveEvent?.authority_policy?.decision_id || 'AUTH-CANONICAL-DECISION';
      const evidenceWindowId = liveEvent?.event_id || 'WIN-001';
      const targetNodeId = 'svc-api';
      const actionType = liveEvent?.recommended_actions?.[0]?.action_type || 'DEMO_BLOCK';

      const res = await apiClient.executeResponseAction({
        action_type: actionType,
        target_node_id: targetNodeId,
        authority_decision_id: decisionId,
        evidence_window_id: evidenceWindowId,
        approval: {
          approval_id: `APP-${Date.now()}`,
          approved,
          approver_reference: approverRef,
          approval_reason: approvalReason,
        },
      });
      setExecutionResult(res);
      if (res.status === 'EXECUTED' || res.status === 'VERIFIED_SUCCESS') {
        isolateSubject(evidenceWindowId);
        setIsolated(true);
      }
    } catch (err: unknown) {
      setExecutionError(err instanceof Error ? err.message : 'Execution failed');
    } finally {
      setIsExecuting(false);
    }
  };

  // Helper to map numeric deltas to BadgeDelta deltaType
  const getDeltaType = (val: number | undefined): 'increase' | 'decrease' | 'neutral' => {
    if (val === undefined || val === 0) return 'neutral';
    return val > 0 ? 'increase' : 'decrease';
  };

  return (
    <div className="p-gutter min-h-full flex flex-col bg-[#000001]">
      {/* Grid Container */}
      <div className="grid grid-cols-12 grid-rows-6 gap-gutter min-h-[850px] w-full bg-[#262626] p-[1px]">
        {/* Region 2: Relationship Graph (8 cols, 4 rows) */}
        <section className="col-span-12 md:col-span-8 row-span-4 bento-bg bento-border relative overflow-hidden group flex flex-col p-8">
          <header className="flex justify-between items-start z-10 mb-4 shrink-0">
            <div className="flex flex-col gap-1">
              <h2 className="font-label-caps text-label-caps uppercase text-white tracking-widest">
                RELATIONSHIP_GRAPH_//
              </h2>
              <span className="font-metadata text-metadata text-[#c6c6c6]">
                DOMAIN: {liveEvent ? `ATTACK_SURFACE // ${liveEvent.primary_stage.toUpperCase()}` : 'GLOBAL_INFRASTRUCTURE'}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-metadata text-[11px] text-[#8e9192] uppercase hidden sm:inline-block">
                STREAM: {connectionState}
              </span>
              <button
                onClick={toggleLiveSync}
                className="bg-[#111111] border border-[#262626] px-3 py-1 font-metadata text-metadata text-white flex items-center gap-2 cursor-pointer hover:border-white transition-colors"
              >
                <span
                  className={`w-2 h-2 rounded-none inline-block ${
                    isLiveSync && connectionState === 'CONNECTED'
                      ? 'bg-[#FFD60A] animate-pulse'
                      : isLiveSync
                      ? 'bg-white animate-pulse'
                      : 'bg-[#8e9192]'
                  }`}
                ></span>
                {isLiveSync ? 'LIVE_SYNC' : 'SYNC_PAUSED'}
              </button>
            </div>
          </header>

          {/* Forensic Canvas Graph Area */}
          <div className="flex-1 relative w-full h-full border border-[#181818] bg-[#000001] overflow-hidden flex flex-col">
            {/* Live Telemetry Deltas Strip / Reserved Top Metric Area */}
            {liveEvent?.current_state_summary && (
              <div className="p-3 border-b border-[#181818] bg-[#080808]/90 flex flex-wrap gap-2 z-10 shrink-0">
                <div className="bg-[#111111] border border-[#262626] px-3 py-1 flex items-center gap-2">
                  <span className="font-metadata text-[10px] text-[#8e9192]">FLOW COUNT</span>
                  <span className="font-metadata text-[11px] text-white font-bold">
                    {liveEvent.current_state_summary.flow_count?.toFixed(0) ?? '0'}
                  </span>
                  <BadgeDelta
                    deltaType={getDeltaType(liveEvent.predicted_deltas_h1?.flow_count_delta)}
                    variant="outline"
                    value={
                      liveEvent.predicted_deltas_h1?.flow_count_delta !== undefined
                        ? `${liveEvent.predicted_deltas_h1.flow_count_delta >= 0 ? '+' : ''}${liveEvent.predicted_deltas_h1.flow_count_delta.toFixed(1)}`
                        : '0.0'
                    }
                  />
                </div>

                <div className="bg-[#111111] border border-[#262626] px-3 py-1 flex items-center gap-2">
                  <span className="font-metadata text-[10px] text-[#8e9192]">PORT DIVERSITY</span>
                  <span className="font-metadata text-[11px] text-white font-bold">
                    {liveEvent.current_state_summary.dst_port_diversity?.toFixed(0) ?? '0'}
                  </span>
                  <BadgeDelta
                    deltaType={getDeltaType(liveEvent.predicted_deltas_h1?.dst_port_diversity_delta)}
                    variant="outline"
                    value={
                      liveEvent.predicted_deltas_h1?.dst_port_diversity_delta !== undefined
                        ? `${liveEvent.predicted_deltas_h1.dst_port_diversity_delta >= 0 ? '+' : ''}${liveEvent.predicted_deltas_h1.dst_port_diversity_delta.toFixed(1)}`
                        : '0.0'
                    }
                  />
                </div>

                <div className="bg-[#111111] border border-[#262626] px-3 py-1 flex items-center gap-2">
                  <span className="font-metadata text-[10px] text-[#8e9192]">BYTE RATE</span>
                  <span className="font-metadata text-[11px] text-white font-bold">
                    {liveEvent.current_state_summary.byte_rate !== undefined
                      ? `${(liveEvent.current_state_summary.byte_rate / 1000).toFixed(1)} KB/s`
                      : '0.0 KB/s'}
                  </span>
                  <BadgeDelta
                    deltaType={getDeltaType(liveEvent.predicted_deltas_h1?.byte_rate_delta)}
                    variant="outline"
                    value={
                      liveEvent.predicted_deltas_h1?.byte_rate_delta !== undefined
                        ? `${liveEvent.predicted_deltas_h1.byte_rate_delta >= 0 ? '+' : ''}${(liveEvent.predicted_deltas_h1.byte_rate_delta / 1000).toFixed(1)}K`
                        : '0.0'
                    }
                  />
                </div>
              </div>
            )}

            {/* Usable Graph Viewport */}
            <div className="flex-1 relative w-full h-full overflow-hidden">
              {/* SVG Network Graphic */}
              <svg
                className="absolute inset-0 w-full h-full"
                style={{
                  transform: `scale(${zoomLevel})`,
                  transformOrigin: 'center center',
                  transition: 'transform 0.2s ease-out',
                }}
                xmlns="http://www.w3.org/2000/svg"
              >
                <defs>
                  <pattern height="40" id="grid-pattern" patternUnits="userSpaceOnUse" width="40">
                    <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#0a0a0a" strokeWidth="1"></path>
                  </pattern>
                </defs>
                <rect fill="url(#grid-pattern)" height="100%" width="100%"></rect>

                {/* Edges */}
                <line className="dash-line" stroke="#454747" strokeWidth="1" x1="20%" x2="50%" y1="30%" y2="50%"></line>
                <line stroke="#454747" strokeWidth="1" x1="80%" x2="50%" y1="20%" y2="50%"></line>
                <line
                  className="pulse-line"
                  stroke={liveEvent && liveEvent.active_signatures.length > 0 ? '#FFD60A' : '#ffffff'}
                  strokeWidth="2"
                  x1="50%"
                  x2="70%"
                  y1="50%"
                  y2="80%"
                ></line>
                <line stroke="#454747" strokeWidth="1" x1="30%" x2="50%" y1="70%" y2="50%"></line>

                {/* Nodes (rendered after edges to sit above edges in z-order) */}
                {OVERVIEW_GRAPH_NODES.map((node: GraphNodeData) => {
                  const isSelected = selectedNodeId === node.id;
                  if (node.id === 'ov-3') {
                    // Primary Selected Node
                    const nodeLabel = liveEvent
                      ? `T${String(liveEvent.step_index).padStart(2, '0')}: ${liveEvent.primary_stage}`
                      : node.label;
                    const nodeSub = liveEvent
                      ? `RISK: ${(liveEvent.current_risk_score * 100).toFixed(0)}% | CONF: ${Math.round(liveEvent.stage_confidence * 100)}%`
                      : node.sublabel;

                    return (
                      <svg
                        key={node.id}
                        x={`${node.x}%`}
                        y={`${node.y}%`}
                        overflow="visible"
                      >
                        <g
                          onClick={() => setSelectedNodeId(node.id)}
                          className="cursor-pointer"
                        >
                          <rect
                            fill="#131313"
                            height="42"
                            stroke={liveEvent && liveEvent.active_signatures.length > 0 ? '#FFD60A' : isSelected ? '#ffffff' : '#ffffff'}
                            strokeWidth="2"
                            width="42"
                            x="-21"
                            y="-21"
                          ></rect>
                          <text
                            fill="#ffffff"
                            fontFamily="JetBrains Mono"
                            fontSize="12"
                            fontWeight="700"
                            x="30"
                            y="-5"
                            paintOrder="stroke"
                            stroke="#000001"
                            strokeWidth="3"
                          >
                            {nodeLabel}
                          </text>
                          <text
                            fill="#c6c6c6"
                            fontFamily="JetBrains Mono"
                            fontSize="10"
                            x="30"
                            y="11"
                            paintOrder="stroke"
                            stroke="#000001"
                            strokeWidth="3"
                          >
                            {nodeSub}
                          </text>
                        </g>
                      </svg>
                    );
                  }
                  if (node.id === 'ov-4') {
                    // Anomaly Node
                    const anomalyLabel =
                      liveEvent && liveEvent.active_signatures.length > 0
                        ? liveEvent.active_signatures[0]
                        : node.label;

                    return (
                      <svg
                        key={node.id}
                        x={`${node.x}%`}
                        y={`${node.y}%`}
                        overflow="visible"
                      >
                        <g
                          onClick={() => setSelectedNodeId(node.id)}
                          className="cursor-pointer"
                        >
                          <circle
                            cx="0"
                            cy="0"
                            fill="#080808"
                            r="16"
                            stroke={liveEvent && liveEvent.active_signatures.length > 0 ? '#FFD60A' : isSelected ? '#ffffff' : '#ffffff'}
                            strokeDasharray="4"
                            strokeWidth="1.5"
                          ></circle>
                          <text
                            fill={liveEvent && liveEvent.active_signatures.length > 0 ? '#FFD60A' : '#ffffff'}
                            fontFamily="JetBrains Mono"
                            fontSize="10"
                            fontWeight="600"
                            x="25"
                            y="4"
                            paintOrder="stroke"
                            stroke="#000001"
                            strokeWidth="3"
                          >
                            {anomalyLabel}
                          </text>
                        </g>
                      </svg>
                    );
                  }
                  // Secondary Nodes (ov-1, ov-2, ov-5)
                  const isRightSide = node.x > 50;
                  return (
                    <svg
                      key={node.id}
                      x={`${node.x}%`}
                      y={`${node.y}%`}
                      overflow="visible"
                    >
                      <g
                        onClick={() => setSelectedNodeId(node.id)}
                        className="cursor-pointer"
                      >
                        <rect
                          fill="#080808"
                          height="30"
                          stroke={isSelected ? '#ffffff' : '#454747'}
                          strokeWidth={isSelected ? '2' : '1'}
                          width="30"
                          x="-15"
                          y="-15"
                        ></rect>
                        <text
                          fill={isSelected ? '#ffffff' : '#e0e0e0'}
                          fontFamily="JetBrains Mono"
                          fontSize="10"
                          fontWeight="600"
                          textAnchor={isRightSide ? 'end' : 'start'}
                          x={isRightSide ? -25 : 25}
                          y="-2"
                          paintOrder="stroke"
                          stroke="#000001"
                          strokeWidth="3"
                        >
                          {node.label}
                        </text>
                        <text
                          fill="#8e9192"
                          fontFamily="JetBrains Mono"
                          fontSize="9"
                          textAnchor={isRightSide ? 'end' : 'start'}
                          x={isRightSide ? -25 : 25}
                          y="11"
                          paintOrder="stroke"
                          stroke="#000001"
                          strokeWidth="3"
                        >
                          {node.sublabel}
                        </text>
                      </g>
                    </svg>
                  );
                })}
              </svg>

              {/* Overlay Controls */}
              <div className="absolute bottom-4 left-4 flex gap-2 z-10">
                <button
                  onClick={() => setZoomLevel((z) => Math.min(z + 0.2, 2))}
                  title="Zoom In"
                  className="bg-[#111111] border border-[#262626] p-1.5 text-[#c6c6c6] hover:text-white hover:border-white transition-colors cursor-pointer"
                >
                  <span className="material-symbols-outlined text-[16px]">zoom_in</span>
                </button>
                <button
                  onClick={() => setZoomLevel((z) => Math.max(z - 0.2, 0.6))}
                  title="Zoom Out"
                  className="bg-[#111111] border border-[#262626] p-1.5 text-[#c6c6c6] hover:text-white hover:border-white transition-colors cursor-pointer"
                >
                  <span className="material-symbols-outlined text-[16px]">zoom_out</span>
                </button>
                <button
                  onClick={() => setZoomLevel(1)}
                  title="Reset View"
                  className="bg-[#111111] border border-[#262626] p-1.5 text-[#c6c6c6] hover:text-white hover:border-white transition-colors cursor-pointer"
                >
                  <span className="material-symbols-outlined text-[16px]">center_focus_strong</span>
                </button>
                <button
                  onClick={() => navigate('/command-center/simulation')}
                  title="Open Simulation"
                  className="bg-[#111111] border border-[#262626] px-2 py-1 text-[10px] font-metadata text-[#c6c6c6] hover:text-white hover:border-white transition-colors cursor-pointer flex items-center gap-1"
                >
                  <span>SIMULATION</span>
                  <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* Region 3: Priority Signal (4 cols, 3 rows) */}
        <section className="col-span-12 md:col-span-4 row-span-3 bento-bg bento-border p-8 flex flex-col border-t-4 border-t-white">
          <header className="flex justify-between items-start mb-6 border-b border-[#262626] pb-2">
            <h2 className="font-title-md text-title-md text-white tracking-widest uppercase">PRIORITY_SIGNAL</h2>
            <span className="font-metadata text-metadata text-black bg-white px-2 py-0.5 font-bold">
              {liveEvent
                ? `T${String(liveEvent.step_index).padStart(2, '0')} // ${liveEvent.primary_stage}`
                : isIdle
                ? 'STANDBY // IDLE'
                : activeCase.id}
            </span>
          </header>

          <div className="flex-1 flex flex-col justify-center">
            <div className="font-display-lg text-display-lg text-white leading-none mb-2">
              {currentConfidencePct}
              <span className="text-[32px] text-[#c6c6c6]">%</span>
            </div>
            <div className="font-label-caps text-label-caps text-[#c6c6c6] mb-6 tracking-widest flex items-center justify-between">
              <span>STAGE_CONFIDENCE</span>
              {liveEvent && (
                <span className="text-[#FFD60A] text-[11px] font-bold">
                  PRIORITY: {liveEvent.priority_level} ({liveEvent.composite_priority.toFixed(2)})
                </span>
              )}
            </div>

            <div className="bg-[#111111] border border-[#262626] p-4 mb-4">
              <div className="flex items-center gap-2 mb-2 text-white">
                <span className="material-symbols-outlined text-[18px] text-[#F0C808]">warning</span>
                <span className="font-label-caps text-label-caps uppercase">
                  {liveEvent
                    ? `SECURITY RISK: ${(liveEvent.current_risk_score * 100).toFixed(1)}%`
                    : 'SIGNAL DETECTED'}
                </span>
              </div>
              <p className="font-body-rg text-[13px] text-[#c6c6c6] mb-3">
                {liveEvent
                  ? liveEvent.risk_explanation || liveEvent.explanation
                  : isIdle
                  ? 'Runtime standby. Click Simulation to start playback or step through telemetry events.'
                  : `Anomalous data exfiltration pattern identified matching signature SIG-994. Target vector originates from ${activeCase.targetVector || 'internal network segment B'}.`}
              </p>
              <div className="flex flex-col gap-1 mt-4">
                <div className="flex justify-between items-center py-1 border-b border-[#181818]">
                  <span className="font-metadata text-metadata text-[#8e9192]">SIGNATURES</span>
                  <span className="font-metadata text-metadata text-white">
                    {liveEvent
                      ? liveEvent.active_signatures.join(', ') || 'NOMINAL'
                      : isIdle
                      ? 'NONE'
                      : 'SIG-994 (DATA_EXFIL)'}
                  </span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-[#181818]">
                  <span className="font-metadata text-metadata text-[#8e9192]">EVENT_ID</span>
                  <span className="font-metadata text-metadata text-white">
                    {liveEvent ? liveEvent.event_id : isIdle ? 'IDLE' : activeCase.subjectId || 'ENT-4921-X'}
                  </span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-[#181818]">
                  <span className="font-metadata text-metadata text-[#8e9192]">AUTHORITY</span>
                  <span className="font-metadata text-metadata text-[#FFD60A]">
                    {liveEvent?.authority_policy?.authority_level || 'RECOMMEND'} (HUMAN_REQUIRED)
                  </span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-[#181818]">
                  <span className="font-metadata text-metadata text-[#8e9192]">TIMESTAMP</span>
                  <span className="font-metadata text-metadata text-white">
                    {liveEvent ? liveEvent.wall_clock_time : isIdle ? 'AWAITING_STREAM' : activeCase.timestamp}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="flex flex-col gap-2 mt-auto">
            <div className="flex justify-between items-center text-[10px] font-metadata text-[#8e9192]">
              <span>RESPONSE GATE:</span>
              <span className="text-white font-bold">
                STAGE 3: OPERATOR CLEARANCE
              </span>
            </div>
            <button
              onClick={() => {
                setExecutionResult(null);
                setExecutionError(null);
                setIsApprovalModalOpen(true);
              }}
              className={`w-full py-3 border font-label-caps text-label-caps uppercase transition-colors cursor-pointer ${
                isolated
                  ? 'bg-[#F0C808] border-[#F0C808] text-black font-bold'
                  : 'border-white text-white hover:bg-white hover:text-black'
              }`}
            >
              {isolated ? 'SUBJECT_ISOLATED (VERIFIED) ✓' : 'ISOLATE_SUBJECT // APPROVAL_REQ'}
            </button>
          </div>
        </section>

        {/* Region 4: Active Investigations (4 cols, 2 rows) */}
        <section className="col-span-12 md:col-span-4 row-span-2 bento-bg bento-border p-8 flex flex-col">
          <header className="flex justify-between items-center mb-4">
            <h2 className="font-label-caps text-label-caps uppercase text-[#c6c6c6]">
              {eventHistory.length > 0 ? 'RECENT_EVENT_STREAM' : 'ACTIVE_INVESTIGATIONS'}
            </h2>
            <span className="material-symbols-outlined text-[16px] text-[#8e9192]">list_alt</span>
          </header>
          <div className="flex-1 flex flex-col gap-[1px] overflow-y-auto">
            {eventHistory.length > 0 ? (
              eventHistory.slice(-3).reverse().map((evt) => {
                const isActive = liveEvent?.step_index === evt.step_index;
                return (
                  <div
                    key={evt.event_id}
                    onClick={() => navigate('/command-center/simulation')}
                    className={`bg-[#111111] flex items-center p-3 cursor-pointer transition-colors ${
                      isActive ? 'border-l-2 border-[#FFD60A]' : 'border-l-2 border-[#262626] hover:bg-[#181818]'
                    }`}
                  >
                    <div className="flex-1">
                      <div className={`font-label-caps text-label-caps ${isActive ? 'text-[#FFD60A]' : 'text-white'}`}>
                        {evt.logical_time_str}
                      </div>
                      <div className="font-metadata text-metadata text-[#8e9192]">{evt.primary_stage}</div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <div className="font-metadata text-metadata text-white">
                          {Math.round(evt.stage_confidence * 100)}%
                        </div>
                        <div className="font-metadata text-metadata text-[#8e9192]">CONF</div>
                      </div>
                      <div className="text-right">
                        <div className="font-metadata text-metadata text-white">
                          {(evt.current_risk_score * 100).toFixed(0)}%
                        </div>
                        <div className="font-metadata text-metadata text-[#8e9192]">RISK</div>
                      </div>
                    </div>
                  </div>
                );
              })
            ) : (
              cases.slice(0, 3).map((item) => {
                const isActive = item.id === activeCase.id;
                return (
                  <div
                    key={item.id}
                    onClick={() => {
                      setActiveCaseId(item.id);
                      navigate('/command-center/investigations');
                    }}
                    className={`bg-[#111111] flex items-center p-3 cursor-pointer transition-colors ${
                      isActive ? 'border-l-2 border-white' : 'border-l-2 border-[#262626] hover:bg-[#181818]'
                    }`}
                  >
                    <div className="flex-1">
                      <div className={`font-label-caps text-label-caps ${isActive ? 'text-white' : 'text-[#c6c6c6]'}`}>
                        {item.id}
                      </div>
                      <div className="font-metadata text-metadata text-[#8e9192]">{item.title}</div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <div className="font-metadata text-metadata text-white">{item.attributionConfidence}%</div>
                        <div className="font-metadata text-metadata text-[#8e9192]">CONF</div>
                      </div>
                      <div className="text-right">
                        <div className="font-metadata text-metadata text-white">{item.evidenceCount}</div>
                        <div className="font-metadata text-metadata text-[#8e9192]">EVID</div>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>

        {/* Region 5: Review Queue (4 cols, 2 rows) */}
        <section className="col-span-12 md:col-span-4 row-span-2 bento-bg bento-border p-8 flex flex-col">
          <header className="flex justify-between items-center mb-4">
            <h2 className="font-label-caps text-label-caps uppercase text-[#c6c6c6]">REVIEW_QUEUE</h2>
            <span className="bg-[#111111] border border-[#262626] px-2 py-0.5 font-metadata text-metadata text-white">
              {liveEvent ? (liveEvent.requires_human ? '1_HUMAN_REVIEW' : '0_PENDING') : 'STANDBY'}
            </span>
          </header>
          <div className="flex-1 flex flex-col gap-2 overflow-y-auto">
            <div
              onClick={() => navigate('/command-center/alerts')}
              className="border border-[#262626] p-3 bg-[#111111] hover:border-white transition-colors cursor-pointer group"
            >
              <div className="flex justify-between items-start mb-2">
                <span className="font-metadata text-metadata text-black bg-[#c6c6c6] px-1">
                  {liveEvent ? `STRATEGY: ${liveEvent.recommended_strategy}` : 'INSUFFICIENT_EVIDENCE'}
                </span>
                <span className="font-metadata text-metadata text-[#8e9192] group-hover:text-white transition-colors">
                  {liveEvent ? `ACTION_01` : 'CASE-031'}
                </span>
              </div>
              <p className="font-body-rg text-[13px] text-[#c6c6c6] line-clamp-2">
                {liveEvent?.recommended_actions?.[0]
                  ? `Recommended: ${liveEvent.recommended_actions[0].action_type} on ${liveEvent.recommended_actions[0].target} (Urgency: ${liveEvent.recommended_actions[0].urgency})`
                  : 'Model requires human validation for baseline behavior deviation on Endpoint-V.'}
              </p>
            </div>
            <div
              onClick={() => navigate('/command-center/alerts')}
              className="border border-[#262626] p-3 bg-[#111111] hover:border-white transition-colors cursor-pointer group"
            >
              <div className="flex justify-between items-start mb-2">
                <span className="font-metadata text-metadata text-white border border-white px-1">
                  {liveEvent?.requires_human ? 'HUMAN_CONFIRMATION' : 'AUTONOMOUS_READY'}
                </span>
                <span className="font-metadata text-metadata text-[#8e9192] group-hover:text-white transition-colors">
                  {liveEvent ? `STEP_${liveEvent.step_index}` : 'SYS-EVENT'}
                </span>
              </div>
              <p className="font-body-rg text-[13px] text-[#c6c6c6] line-clamp-2">
                {liveEvent
                  ? liveEvent.explanation
                  : 'Unrecognized protocol execution in sector 4. Requires manual classification.'}
              </p>
            </div>
          </div>
        </section>

        {/* Region 6: System State (4 cols, 1 row) */}
        <section className="col-span-12 md:col-span-4 row-span-1 bento-bg bento-border p-8 flex flex-col justify-center">
          <div className="flex justify-between items-center mb-2">
            <h2 className="font-label-caps text-label-caps uppercase text-[#c6c6c6]">SYSTEM_STATE</h2>
            <span className="material-symbols-outlined text-[16px] text-white">dns</span>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div className="flex flex-col">
              <span className="font-metadata text-metadata text-[#8e9192] mb-1">INGESTION</span>
              <span className="font-title-md text-title-md text-white">
                {liveEvent?.current_state_summary?.byte_rate !== undefined
                  ? `${(liveEvent.current_state_summary.byte_rate / 1000).toFixed(1)}`
                  : isIdle
                  ? '0.0'
                  : '4.2'}
                <span className="text-sm font-normal text-[#c6c6c6] ml-1">
                  {liveEvent ? 'KB/s' : 'GB/s'}
                </span>
              </span>
            </div>
            <div className="flex flex-col border-l border-[#262626] pl-4">
              <span className="font-metadata text-metadata text-[#8e9192] mb-1">MODEL_STATUS</span>
              <span className="font-title-md text-title-md text-white">
                AR(5)<span className="text-sm font-normal text-[#c6c6c6] ml-1">AUTH</span>
              </span>
            </div>
            <div className="flex flex-col border-l border-[#262626] pl-4">
              <span className="font-metadata text-metadata text-[#8e9192] mb-1">OBSERVABILITY</span>
              <span className="font-title-md text-title-md text-white">
                {currentTrustPct}
                <span className="text-sm font-normal text-[#c6c6c6] ml-1">%</span>
              </span>
            </div>
          </div>
          <div className="w-full h-[2px] bg-[#181818] mt-4 relative">
            <div
              className="absolute left-0 top-0 h-full bg-white transition-all duration-300"
              style={{ width: `${Math.min(currentTrustPct, 100)}%` }}
            ></div>
          </div>
        </section>
      </div>

      {/* Operator Approval & Authority Review Modal */}
      {isApprovalModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0c0c0c] border border-[#333333] w-full max-w-2xl flex flex-col p-6 shadow-2xl">
            <div className="flex justify-between items-start border-b border-[#222222] pb-4 mb-4">
              <div>
                <div className="font-label-caps text-label-caps uppercase text-[#FFD60A] tracking-widest text-[11px] mb-1">
                  STAGE 3: RESPONSE AUTHORIZATION GATE
                </div>
                <h3 className="font-title-md text-white text-lg tracking-wide uppercase">
                  OPERATOR APPROVAL & AUTHORITY REVIEW
                </h3>
              </div>
              <button
                onClick={() => setIsApprovalModalOpen(false)}
                className="text-[#8e9192] hover:text-white p-1 cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="flex flex-col gap-4 text-xs font-metadata text-[#c6c6c6]">
              {/* Evidence & Decision Context */}
              <div className="bg-[#141414] border border-[#262626] p-4 flex flex-col gap-2">
                <div className="flex justify-between">
                  <span className="text-[#8e9192]">EVALUATION CASE:</span>
                  <span className="text-white font-bold">CASE-019 (demo_recon_15s)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#8e9192]">NETWORK TARGET:</span>
                  <span className="text-white font-bold">svc-api (Gateway Node 4 Ingress)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#8e9192]">EVIDENCE WINDOW ID:</span>
                  <span className="text-white font-mono">{liveEvent?.event_id || 'WIN-001'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#8e9192]">AUTHORITY DECISION ID:</span>
                  <span className="text-white font-mono">
                    {liveEvent?.authority_policy?.decision_id || 'AUTH-CANONICAL-DECISION'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#8e9192]">AUTHORITY LEVEL:</span>
                  <span className="text-[#FFD60A] font-bold">
                    {liveEvent?.authority_policy?.authority_level || 'RECOMMEND'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#8e9192]">PROPOSED ACTION:</span>
                  <span className="text-white font-bold">
                    {liveEvent?.recommended_actions?.[0]?.action_type || 'DEMO_BLOCK'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#8e9192]">ACTION CLASS:</span>
                  <span className="text-[#4ade80]">REVERSIBLE_CONTAINMENT (NON-DESTRUCTIVE)</span>
                </div>
              </div>

              {/* Invariant Warning */}
              <div className="bg-[#1f1905] border border-[#523e02] p-3 text-[#fde047] text-[11px] leading-relaxed">
                <strong>INVARIANTS 1 & 4 ENFORCED:</strong> Permanent disruption actions are permanently blocked.
                This reversible containment action requires explicit human clearance and is verified against
                active packet-drop telemetry.
              </div>

              {/* Operator Inputs */}
              <div className="flex flex-col gap-3">
                <div className="flex flex-col gap-1">
                  <label className="text-[#8e9192] uppercase font-bold text-[10px]">
                    OPERATOR / APPROVER REFERENCE
                  </label>
                  <input
                    type="text"
                    value={approverRef}
                    onChange={(e) => setApproverRef(e.target.value)}
                    className="bg-[#111111] border border-[#333333] p-2 text-white font-mono focus:border-white outline-none"
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[#8e9192] uppercase font-bold text-[10px]">
                    OPERATOR JUSTIFICATION / REASON
                  </label>
                  <input
                    type="text"
                    value={approvalReason}
                    onChange={(e) => setApprovalReason(e.target.value)}
                    className="bg-[#111111] border border-[#333333] p-2 text-white font-mono focus:border-white outline-none"
                  />
                </div>
              </div>

              {/* Execution Status / Error / Result */}
              {executionResult && (
                <div
                  className={`p-3 border text-[11px] ${
                    executionResult.status === 'EXECUTED' || executionResult.status === 'VERIFIED_SUCCESS'
                      ? 'bg-[#052e16] border-[#166534] text-[#86efac]'
                      : 'bg-[#3b0712] border-[#881337] text-[#fca5a5]'
                  }`}
                >
                  <div className="font-bold mb-1">
                    STATUS: {executionResult.status} {executionResult.is_verified ? '(VERIFIED)' : ''}
                  </div>
                  <div>{executionResult.message}</div>
                  {executionResult.error_message && (
                    <div className="mt-1 text-[#fca5a5] font-mono">
                      {executionResult.error_message}
                    </div>
                  )}
                  {executionResult.verification_status && (
                    <div className="mt-1 text-[#4ade80]">
                      Verification: {executionResult.verification_status}
                    </div>
                  )}
                </div>
              )}

              {executionError && (
                <div className="p-3 border bg-[#3b0712] border-[#881337] text-[#fca5a5] text-[11px]">
                  <strong>EXECUTION BLOCKED / ERROR:</strong> {executionError}
                </div>
              )}
            </div>

            {/* Modal Actions */}
            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-[#222222]">
              <button
                onClick={() => setIsApprovalModalOpen(false)}
                className="px-4 py-2 border border-[#333333] text-[#8e9192] hover:text-white font-metadata text-xs uppercase cursor-pointer"
              >
                CANCEL
              </button>
              <button
                onClick={() => handleExecuteApproval(false)}
                disabled={isExecuting}
                className="px-4 py-2 border border-[#881337] bg-[#3b0712] hover:bg-[#881337] text-white font-metadata text-xs uppercase cursor-pointer disabled:opacity-50"
              >
                REJECT & LOG AUDIT
              </button>
              <button
                onClick={() => handleExecuteApproval(true)}
                disabled={isExecuting}
                className="px-4 py-2 border border-[#FFD60A] bg-[#FFD60A] hover:bg-white text-black font-bold font-metadata text-xs uppercase cursor-pointer disabled:opacity-50"
              >
                {isExecuting ? 'EXECUTING...' : 'APPROVE & EXECUTE DEFENSE'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
