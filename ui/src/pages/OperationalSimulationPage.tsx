import React, { useState, useEffect, useRef } from 'react';
import { useRuntimeStore } from '../store/useRuntimeStore';

interface OperatorCommandEntry {
  id: string;
  timestamp: string;
  actor: '[OPERATOR]' | '[ENGINE]' | '[ALERT]' | '[STATUS]' | '[RECONSIDER]';
  text: string;
  isAccent?: boolean;
  isNew?: boolean;
}

const SPEED_OPTIONS = [0.5, 1.0, 2.0, 5.0];

export const OperationalSimulationPage: React.FC = () => {
  const {
    snapshot,
    eventHistory,
    demoStatus,
    connectionState,
    startDemo,
    pauseDemo,
    resumeDemo,
    stepDemo,
    resetDemo,
    setSpeed,
  } = useRuntimeStore();

  const [focusedStepIndex, setFocusedStepIndex] = useState<number | null>(null);
  const [showHumanReviewOverlay, setShowHumanReviewOverlay] = useState<boolean>(false);
  const [operatorLogs, setOperatorLogs] = useState<OperatorCommandEntry[]>([
    {
      id: 'cmd-init',
      timestamp: '[BOOT]',
      actor: '[ENGINE]',
      text: `Runtime engine ready. Scenario: ${demoStatus.scenario || 'demo_recon_15s'} (${demoStatus.total_steps || 16} steps total). Session: ${demoStatus.session_id || 'IDLE'}.`,
    },
  ]);
  const terminalRef = useRef<HTMLDivElement>(null);

  const liveEvent = snapshot.event;
  const isRunning = demoStatus.status === 'RUNNING';
  const isPaused = demoStatus.status === 'PAUSED';
  const isIdle = demoStatus.status === 'IDLE';
  const isCompleted = demoStatus.status === 'COMPLETED';

  const confidence = liveEvent ? Math.round(liveEvent.stage_confidence * 100) : 0;
  const observability = liveEvent ? Math.round(liveEvent.composite_trust * 100) : 0;
  const caseState = liveEvent ? liveEvent.primary_stage : (isIdle ? 'IDLE' : 'MONITORING');
  const attackSignal =
    liveEvent && liveEvent.active_signatures.length > 0
      ? liveEvent.active_signatures.join(', ')
      : 'NONE DETECTED';
  const authorityState = liveEvent
    ? liveEvent.requires_human
      ? 'HUMAN ADVISORY'
      : 'ACTIVE'
    : 'STANDBY';

  const currentSpeed = demoStatus.speed || 1.0;

  // Append backend event notifications to the live command log
  const prevStepRef = useRef<number>(-1);
  useEffect(() => {
    if (liveEvent && liveEvent.step_index !== prevStepRef.current) {
      prevStepRef.current = liveEvent.step_index;
      const isAccent =
        liveEvent.active_signatures.length > 0 ||
        (liveEvent.primary_stage !== 'Unknown' && liveEvent.primary_stage !== 'Unknown / Benign');
      const actionsStr =
        liveEvent.recommended_actions?.map((a) => a.action_type).join(', ') || 'MONITOR';

      const entry: OperatorCommandEntry = {
        id: `evt-${liveEvent.step_index}-${Date.now()}`,
        timestamp: `[${liveEvent.logical_time_str || 'T--'}]`,
        actor: liveEvent.active_signatures.length > 0 ? '[ALERT]' : '[ENGINE]',
        text: `Step ${liveEvent.step_index}: Stage='${liveEvent.primary_stage}' | Risk=${((liveEvent.current_risk_score ?? 0) * 100).toFixed(1)}% | Trust=${((liveEvent.composite_trust ?? 0) * 100).toFixed(1)}% | Strategy: ${liveEvent.recommended_strategy || 'MONITOR'} [${actionsStr}]`,
        isAccent,
        isNew: true,
      };

      setOperatorLogs((prev) => [...prev.slice(-99), entry]);
    }
  }, [liveEvent]);

  // Log status transitions
  const prevStatusRef = useRef<string>(demoStatus.status);
  useEffect(() => {
    if (demoStatus.status !== prevStatusRef.current) {
      const entry: OperatorCommandEntry = {
        id: `status-${demoStatus.status}-${Date.now()}`,
        timestamp: `[${new Date().toLocaleTimeString()}]`,
        actor: '[STATUS]',
        text: `Runtime engine transitioned from ${prevStatusRef.current} -> ${demoStatus.status}`,
        isAccent: demoStatus.status === 'RUNNING',
      };
      prevStatusRef.current = demoStatus.status;
      setOperatorLogs((prev) => [...prev.slice(-99), entry]);
    }
  }, [demoStatus.status]);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [operatorLogs.length]);

  const addOperatorCmdLog = (text: string) => {
    const entry: OperatorCommandEntry = {
      id: `cmd-${Date.now()}`,
      timestamp: `[${new Date().toLocaleTimeString()}]`,
      actor: '[OPERATOR]',
      text,
      isAccent: true,
      isNew: true,
    };
    setOperatorLogs((prev) => [...prev.slice(-99), entry]);
  };

  const handleStartSimulation = async () => {
    try {
      addOperatorCmdLog(`START requested (scenario: demo_recon_15s, speed: ${currentSpeed}x)`);
      await startDemo('demo_recon_15s', currentSpeed);
    } catch (err) {
      addOperatorCmdLog(`ERROR: Start failed - ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handlePauseResume = async () => {
    try {
      if (isPaused) {
        addOperatorCmdLog('RESUME command issued');
        await resumeDemo();
      } else if (isRunning) {
        addOperatorCmdLog('PAUSE command issued');
        await pauseDemo();
      }
    } catch (err) {
      addOperatorCmdLog(`ERROR: Pause/Resume failed - ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleStep = async () => {
    try {
      addOperatorCmdLog('STEP command issued (advancing exactly 1 window)');
      await stepDemo();
    } catch (err) {
      addOperatorCmdLog(`ERROR: Step failed - ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleReset = async () => {
    try {
      addOperatorCmdLog('RESET command issued (clearing telemetry buffer and state store)');
      setShowHumanReviewOverlay(false);
      setFocusedStepIndex(null);
      prevStepRef.current = -1;
      await resetDemo();
    } catch (err) {
      addOperatorCmdLog(`ERROR: Reset failed - ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleSpeedChange = async (speed: number) => {
    try {
      addOperatorCmdLog(`SPEED adjustment issued: ${speed}x`);
      await setSpeed(speed);
    } catch (err) {
      addOperatorCmdLog(`ERROR: Speed change failed - ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const safeHistory = Array.isArray(eventHistory) ? eventHistory : [];

  // Parse future risk scores for AR(5) forecast overlay (strictly from backend, no client math)
  const futureForecastEntries = liveEvent?.future_risk_scores
    ? Object.entries(liveEvent.future_risk_scores).map(([horizon, score], idx) => ({
        horizon,
        stepOffset: idx + 1,
        riskScore: Number(score),
      }))
    : [];

  return (
    <div className="flex flex-col h-full bg-[#000001] text-white overflow-hidden p-8">
      {/* Simulation Controls Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end mb-6 gap-4 border-b border-[#262626] pb-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h2 className="font-headline-lg text-headline-lg text-white uppercase tracking-tight">
              OPERATIONAL SIMULATION
            </h2>
            <span
              className={`px-2 py-0.5 font-label-caps text-[9px] uppercase border ${
                connectionState === 'CONNECTED'
                  ? 'border-[#262626] text-[#F0C808] bg-[#111111]'
                  : 'border-[#ffb4ab] text-[#ffb4ab] bg-[#1a0c0c]'
              }`}
            >
              SSE: {connectionState}
            </span>
            <span
              className={`px-2 py-0.5 font-label-caps text-[9px] uppercase border font-bold ${
                demoStatus.execution_mode === 'LIVE_PACKET_CAPTURE'
                  ? 'border-[#00ff88] text-[#00ff88] bg-[#002b15]'
                  : 'border-[#262626] text-[#c6c6c6] bg-[#080808]'
              }`}
            >
              MODE: {demoStatus.execution_mode === 'LIVE_PACKET_CAPTURE' ? 'LIVE PACKET CAPTURE (Npcap/TShark)' : 'DEMO REPLAY'}
            </span>
          </div>
          <p className="font-metadata text-metadata text-[#8e9192]">
            {demoStatus.execution_mode === 'LIVE_PACKET_CAPTURE'
              ? `LIVE CAPTURE: ${(demoStatus.scenario || 'LIVE_PCAP').toUpperCase()} // NPCAP 1.88 + TSHARK // LOOPBACK // SESSION: ${demoStatus.session_id || 'STANDBY'}`
              : `SCENARIO: ${(demoStatus.scenario || 'demo_recon_15s').toUpperCase()} // AR(5) REPLAY & INTELLIGENCE PIPELINE // SESSION: ${demoStatus.session_id || 'STANDBY'}`}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Status Indicator */}
          <div className="flex items-center gap-2 mr-2 bg-[#111111] border border-[#262626] px-3 py-1 pulse-glow">
            <div
              className={`w-2 h-2 rounded-full ${
                isRunning
                  ? 'bg-[#F0C808] animate-pulse'
                  : isPaused
                  ? 'bg-[#ffffff]'
                  : isCompleted
                  ? 'bg-[#8e9192]'
                  : 'bg-[#707070]'
              }`}
            ></div>
            <span className="font-metadata text-metadata text-[#F0C808] uppercase font-bold">
              STATUS: {demoStatus.status}{' '}
              {demoStatus.current_step >= 0 ? `(T${String(demoStatus.current_step).padStart(2, '0')}/${demoStatus.total_steps})` : ''}
            </span>
          </div>

          {/* Playback Speed Multiplier Pills */}
          <div className="flex items-center border border-[#262626] bg-[#080808] p-0.5">
            <span className="font-metadata text-[10px] text-[#8e9192] px-2 uppercase">SPEED:</span>
            {SPEED_OPTIONS.map((spd) => (
              <button
                key={spd}
                onClick={() => handleSpeedChange(spd)}
                className={`px-2 py-1 font-label-caps text-[10px] transition-colors cursor-pointer ${
                  Math.abs(currentSpeed - spd) < 0.01
                    ? 'bg-[#F0C808] text-black font-bold'
                    : 'text-[#c6c6c6] hover:text-white'
                }`}
              >
                {spd}x
              </button>
            ))}
          </div>

          {/* Action Buttons */}
          <button
            onClick={handleReset}
            className="px-4 py-2 border border-[#262626] text-white hover:border-white font-label-caps text-label-caps uppercase transition-colors cursor-pointer"
          >
            RESET
          </button>
          <button
            onClick={handleStep}
            className="px-4 py-2 border border-[#262626] text-white hover:border-white font-label-caps text-label-caps uppercase transition-colors cursor-pointer"
          >
            STEP
          </button>
          <button
            onClick={handlePauseResume}
            disabled={isIdle || isCompleted}
            className={`px-4 py-2 border border-[#262626] font-label-caps text-label-caps uppercase transition-colors cursor-pointer ${
              isIdle || isCompleted
                ? 'opacity-40 cursor-not-allowed text-[#707070]'
                : 'text-white hover:border-white'
            }`}
          >
            {isPaused ? 'RESUME' : 'PAUSE'}
          </button>
          <button
            onClick={handleStartSimulation}
            className="px-4 py-2 bg-white text-black font-label-caps text-label-caps uppercase font-bold hover:bg-[#c6c6c6] transition-colors cursor-pointer flex items-center gap-2"
          >
            <span className="material-symbols-outlined text-[16px]">play_arrow</span>
            START SIMULATION
          </button>
        </div>
      </div>

      {/* Bento Grid Layout (3 cols, 6 cols, 3 cols) */}
      <div className="grid grid-cols-12 gap-gutter bg-[#262626] border border-[#262626] flex-1 min-h-[640px]">
        {/* Col 1: Vitals & Context (Span 3) */}
        <div className="col-span-12 lg:col-span-3 bg-[#080808] flex flex-col p-6 relative">
          <div className="flex justify-between items-center font-label-caps text-label-caps uppercase text-white mb-6 border-b border-[#262626] pb-2">
            <span>ENGINE VITALITY</span>
            <span className="text-[#8e9192]">SYS-01</span>
          </div>

          <div className="mb-6">
            <div className="flex justify-between font-metadata text-metadata mb-2">
              <span className="text-[#8e9192]">STAGE CONFIDENCE</span>
              <span className="text-white font-bold">{confidence}%</span>
            </div>
            <div className="w-full h-1 bg-[#181818]">
              <div className="h-full bg-white transition-all duration-700" style={{ width: `${confidence}%` }}></div>
            </div>
          </div>

          <div className="mb-6">
            <div className="flex justify-between font-metadata text-metadata mb-2">
              <span className="text-[#8e9192]">COMPOSITE TRUST</span>
              <span className={`font-bold ${observability < 70 && liveEvent ? 'text-[#ffb4ab]' : 'text-white'}`}>
                {observability}%
              </span>
            </div>
            <div className="w-full h-1 bg-[#181818]">
              <div
                className={`h-full transition-all duration-700 ${
                  observability < 70 && liveEvent ? 'bg-[#ffb4ab]' : 'bg-white'
                }`}
                style={{ width: `${observability}%` }}
              ></div>
            </div>
          </div>

          <div className="mb-8">
            <div className="flex justify-between font-metadata text-metadata mb-2">
              <span className="text-[#8e9192]">CURRENT RISK SCORE</span>
              <span className="text-[#F0C808] font-bold">
                {liveEvent ? `${((liveEvent.current_risk_score ?? 0) * 100).toFixed(1)}%` : '0.0%'}
              </span>
            </div>
            <div className="w-full h-1 bg-[#181818]">
              <div
                className="h-full bg-[#F0C808] transition-all duration-700"
                style={{ width: `${liveEvent ? (liveEvent.current_risk_score ?? 0) * 100 : 0}%` }}
              ></div>
            </div>
          </div>

          <div className="mt-auto">
            <div className="flex justify-between items-center font-label-caps text-label-caps uppercase text-white mb-2">
              <span>SECURITY STAGE</span>
              <span className="text-[#8e9192]">NOW</span>
            </div>
            <div
              className={`p-4 border transition-colors ${
                caseState !== 'Unknown' && caseState !== 'Unknown / Benign' && caseState !== 'IDLE'
                  ? 'border-[#F0C808] bg-[#111111]'
                  : 'border-[#262626] bg-[#0A0A0A]'
              }`}
            >
              <div className="font-metadata text-metadata text-[#8e9192] mb-1">CLASSIFICATION</div>
              <div
                className={`font-label-caps text-label-caps tracking-widest ${
                  caseState !== 'Unknown' && caseState !== 'Unknown / Benign' && caseState !== 'IDLE'
                    ? 'text-[#F0C808] font-bold'
                    : 'text-white'
                }`}
              >
                {caseState}
              </div>
            </div>
          </div>
        </div>

        {/* Col 2: Stream, Trajectory & Ledger (Span 6) */}
        <div className="col-span-12 lg:col-span-6 bg-[#080808] flex flex-col border-x border-[#262626] relative overflow-hidden">
          {/* Live Network Trajectory & AR(5) Forecast Overlay */}
          <div className="p-6 border-b border-[#262626] bg-[#060606] shrink-0">
            <div className="flex justify-between items-center font-label-caps text-label-caps uppercase text-white mb-3 border-b border-[#262626] pb-2">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 bg-[#F0C808]"></span>
                <span>NETWORK TRAJECTORY // AR(5) FORECAST CONE</span>
              </div>
              <div className="flex items-center gap-4 text-[#8e9192] font-metadata text-[10px]">
                <span className="flex items-center gap-1.5">
                  <span className="w-3 h-0.5 bg-white inline-block"></span> OBSERVED
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-3 h-0.5 border-t border-dashed border-[#F0C808] inline-block"></span> AR(5) FORECAST
                </span>
              </div>
            </div>

            {/* Trajectory Grid & Bars */}
            <div className="h-32 flex items-end gap-1.5 pt-2 pb-1 px-2 bg-[#0B0B0B] border border-[#1c1c1c] relative">
              {safeHistory.length === 0 ? (
                <div className="w-full h-full flex items-center justify-center font-metadata text-metadata text-[#707070] italic">
                  Telemetry buffer empty. Click START SIMULATION to stream live trajectory.
                </div>
              ) : (
                <>
                  {/* Historical Observed Telemetry Steps */}
                  {safeHistory.slice(-12).map((evt) => {
                    const heightPct = Math.max(8, Math.min(100, Math.round((evt.current_risk_score ?? 0) * 100)));
                    const isCurrent = evt.step_index === demoStatus.current_step;
                    const isElevated = (evt.current_risk_score ?? 0) > 0.3;

                    return (
                      <div
                        key={evt.event_id}
                        title={`Step ${evt.step_index}: Risk ${(evt.current_risk_score * 100).toFixed(1)}%`}
                        className="flex-1 flex flex-col items-center h-full justify-end group cursor-pointer"
                        onClick={() => setFocusedStepIndex(evt.step_index)}
                      >
                        <div
                          className={`w-full transition-all duration-300 ${
                            isCurrent
                              ? 'bg-white shadow-[0_0_8px_rgba(255,255,255,0.6)]'
                              : isElevated
                              ? 'bg-[#F0C808]'
                              : 'bg-[#353535] group-hover:bg-[#555555]'
                          }`}
                          style={{ height: `${heightPct}%` }}
                        ></div>
                        <span className="font-metadata text-[8px] text-[#8e9192] mt-1">
                          T{String(evt.step_index).padStart(2, '0')}
                        </span>
                      </div>
                    );
                  })}

                  {/* Forward AR(5) Forecast Trajectory Projection (from backend future_risk_scores) */}
                  {futureForecastEntries.map((fc) => {
                    const heightPct = Math.max(8, Math.min(100, Math.round(fc.riskScore * 100)));
                    return (
                      <div
                        key={fc.horizon}
                        title={`Forecast ${fc.horizon}: Risk ${(fc.riskScore * 100).toFixed(1)}% (AR-5)`}
                        className="flex-1 flex flex-col items-center h-full justify-end opacity-85"
                      >
                        <div
                          className="w-full border-t-2 border-r-2 border-l-2 border-dashed border-[#F0C808] bg-[#F0C808]/20 transition-all duration-300"
                          style={{ height: `${heightPct}%` }}
                        ></div>
                        <span className="font-metadata text-[8px] text-[#F0C808] font-bold mt-1">
                          {fc.horizon}
                        </span>
                      </div>
                    );
                  })}
                </>
              )}
            </div>
          </div>

          {/* Live Command Log */}
          <div className="flex-1 p-6 flex flex-col overflow-hidden border-b border-[#262626]">
            <div className="flex justify-between items-center font-label-caps text-label-caps uppercase text-white mb-3 border-b border-[#262626] pb-2">
              <div className="flex items-center gap-2">
                <span>OPERATIONAL COMMAND LOG</span>
                <div
                  className={`w-1.5 h-1.5 rounded-full ${
                    isRunning ? 'bg-[#F0C808] pulse-live' : 'bg-[#707070]'
                  }`}
                ></div>
              </div>
              <span className="text-[#8e9192]">ENTRIES: {operatorLogs.length}</span>
            </div>

            <div ref={terminalRef} className="flex-1 overflow-y-auto space-y-2 font-metadata text-metadata pr-2">
              {operatorLogs.map((log) => (
                <div
                  key={log.id}
                  className={`py-1 ${
                    log.isNew ? 'animate-feed-stream border-l-2 border-[#F0C808] pl-2' : ''
                  }`}
                >
                  <span className="text-[#8e9192] mr-2">{log.timestamp}</span>
                  <span
                    className={`font-bold mr-2 ${
                      log.actor === '[OPERATOR]'
                        ? 'text-[#ffffff] underline'
                        : log.actor === '[ALERT]'
                        ? 'text-[#F0C808]'
                        : log.actor === '[STATUS]'
                        ? 'text-[#c6c6c6]'
                        : 'text-[#8e9192]'
                    }`}
                  >
                    {log.actor}
                  </span>
                  <span className={log.isAccent ? 'text-[#F0C808]' : 'text-[#c6c6c6]'}>
                    {log.text}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Event Timeline Ledger */}
          <div className="h-40 p-6 bg-[#0B0B0B] flex flex-col justify-between overflow-y-auto shrink-0">
            <div className="flex justify-between items-center font-label-caps text-label-caps uppercase text-white mb-2">
              <span>EVENT TIMELINE LEDGER</span>
              <span className="text-[#8e9192]">HISTORY: {safeHistory.length} STEPS</span>
            </div>
            <div className="divide-y divide-[#262626] font-metadata text-metadata">
              {safeHistory.slice(-4).map((evt) => (
                <div
                  key={evt.event_id}
                  onClick={() => setFocusedStepIndex(evt.step_index)}
                  className={`py-1.5 px-2 flex justify-between items-center cursor-pointer transition-colors ${
                    focusedStepIndex === evt.step_index || evt.step_index === demoStatus.current_step
                      ? 'border-l-2 border-[#F0C808] bg-[#111111] text-white'
                      : 'text-[#c6c6c6] hover:bg-[#181818]'
                  }`}
                >
                  <span className="text-white font-bold">{evt.logical_time_str}</span>
                  <span className="text-[#8e9192]">{evt.primary_stage}</span>
                  <span className="text-[#8e9192]">RISK: {((evt.current_risk_score ?? 0) * 100).toFixed(0)}%</span>
                  <span className="text-white font-bold">{evt.priority_level}</span>
                </div>
              ))}
              {safeHistory.length === 0 && (
                <div className="py-2 text-[#707070] italic">
                  No steps recorded yet. Click START SIMULATION to stream.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Col 3: Intel & Authority (Span 3) */}
        <div className="col-span-12 lg:col-span-3 bg-[#080808] flex flex-col p-6 relative">
          <div className="flex justify-between items-center font-label-caps text-label-caps uppercase text-white mb-2">
            <span>ATTACK SIGNALS</span>
            <span className="text-[#8e9192]">ACTIVE</span>
          </div>
          <div
            className={`border p-4 mb-6 transition-colors ${
              attackSignal !== 'NONE DETECTED'
                ? 'border-[#F0C808] bg-[#111111] animate-focus-flash'
                : 'border-[#262626] bg-[#0A0A0A]'
            }`}
          >
            <div className="font-metadata text-metadata text-[#8e9192] mb-1">SIGNATURE DETECTIONS</div>
            <div
              className={`font-label-caps text-label-caps tracking-widest text-[12px] ${
                attackSignal !== 'NONE DETECTED' ? 'text-[#F0C808] font-bold' : 'text-white'
              }`}
            >
              {attackSignal}
            </div>
          </div>

          <div className="flex justify-between items-center font-label-caps text-label-caps uppercase text-white mb-2">
            <span>DECISION AUTHORITY</span>
            <span className="text-[#8e9192]">POLICY GATE</span>
          </div>
          <div className="border border-[#262626] bg-[#0A0A0A] p-4 mb-6">
            <div className="font-metadata text-metadata text-[#8e9192] mb-1">HUMAN APPROVAL REQUIRED</div>
            <div
              className={`font-label-caps text-label-caps tracking-widest ${
                authorityState === 'HUMAN ADVISORY'
                  ? 'text-[#F0C808] font-bold'
                  : 'text-white'
              }`}
            >
              {authorityState}
            </div>
            <p className="font-metadata text-[10px] text-[#8e9192] mt-2 leading-tight">
              {liveEvent?.requires_human
                ? 'Automated destructive action blocked. Human validation required before containment.'
                : 'Policy gate standing by for telemetry elevation.'}
            </p>
          </div>

          <div className="mt-auto">
            <div className="flex justify-between items-center font-label-caps text-label-caps uppercase text-white mb-2 border-b border-[#262626] pb-1">
              <span>RECOMMENDED ACTION</span>
              <span className="text-[#8e9192]">NOW</span>
            </div>
            <div className="divide-y divide-[#262626] font-metadata text-metadata">
              <div className="py-2 flex justify-between">
                <span className="text-white">STRATEGY</span>
                <span className="text-[#F0C808] font-bold">
                  {liveEvent ? liveEvent.recommended_strategy : 'MONITOR'}
                </span>
              </div>
              <div className="py-2 flex justify-between">
                <span className="text-[#8e9192]">ACTION</span>
                <span className="text-[#8e9192]">
                  {liveEvent?.recommended_actions?.[0]?.action_type || 'INCREASE_MONITORING'}
                </span>
              </div>
              <div className="py-2 flex justify-between">
                <span className="text-[#8e9192]">PRIORITY</span>
                <span className="text-white font-bold">
                  {liveEvent ? `${liveEvent.priority_level}` : 'LOW'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Human Review Overlay Modal */}
      {showHumanReviewOverlay && (
        <div className="fixed inset-0 z-50 bg-black/80 flex flex-col items-center justify-center backdrop-blur-xs animate-fade-in">
          <div className="border-2 border-white p-10 bg-[#080808] text-center max-w-md shadow-2xl">
            <span className="material-symbols-outlined text-4xl mb-4 text-white">front_hand</span>
            <h2 className="font-headline-lg text-headline-lg text-white mb-2 uppercase">
              HUMAN REVIEW REQUIRED
            </h2>
            <p className="font-metadata text-metadata text-[#8e9192] mb-8 leading-relaxed">
              Automated actions require human authorization. All counter-measures are advisory and reversible.
            </p>
            <button
              onClick={() => setShowHumanReviewOverlay(false)}
              className="w-full py-3 bg-white text-black font-label-caps text-label-caps uppercase font-bold hover:bg-[#c6c6c6] transition-colors cursor-pointer"
            >
              ACKNOWLEDGE &amp; ASSUME CONTROL
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
