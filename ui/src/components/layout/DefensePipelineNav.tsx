import React from 'react';
import { Link } from 'react-router-dom';
import { TraceText, OrbitText } from '../common/EncasedHover';
import { MetallicShimmerText } from '../common/MetallicShimmerText';

export interface PipelineStageItem {
  readonly id: string;
  readonly label: string;
  readonly verb: string;
  readonly path: string;
}

export interface DefensePipelineNavProps {
  stages?: readonly PipelineStageItem[];
  selectedScenario: string;
  availableScenarios: readonly { scenario_id: string; display_name: string }[];
  onSelectScenario: (scenarioId: string) => void;
  demoStatus: { status: string; total_steps: number };
  currentStepIndex?: number;
  onStartDemo: () => void;
  onPauseDemo: () => void;
  onResumeDemo: () => void;
  onStepDemo: () => void;
  onResetDemo: () => void;
  connectionState: string;
  isLive: boolean;
  executionMode: string;
  riskScore?: number;
  className?: string;
}

/**
 * ── Subcomponent 1: Product Identity & Navigation Drawer Trigger ─────────────
 * Provides compact application identity and trigger for the single authoritative
 * left-side Defense Pipeline drawer.
 */
export const DefenseIdentity: React.FC = () => {
  return (
    <div className="flex items-center gap-3 shrink-0 font-mono">
      <label
        htmlFor="pipeline-nav-toggle"
        className="pipeline-burger cursor-pointer md:hidden"
        aria-label="Toggle defense pipeline drawer"
        title="Open Defense Pipeline Navigation Drawer"
        data-cursor="interactive"
      >
        <span />
        <span />
        <span />
      </label>

      <Link
        to="/"
        className="flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 transition-colors group"
        title="Return to Landing Page"
        data-cursor="interactive"
      >
        <span className="text-zinc-500 group-hover:text-[#F0C808] transition-colors text-xs font-mono">◂</span>
        <div className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-[#F0C808] shadow-[0_0_6px_#F0C808]" />
          <MetallicShimmerText
            as="span"
            variant="gold"
            mode="sweep"
            className="text-xs font-bold tracking-wider"
          >
            CONTROL CENTRE
          </MetallicShimmerText>
        </div>
      </Link>
    </div>
  );
};

/**
 * ── Subcomponent 2: Contextual Scenario Selector ─────────────────────────────
 * Secondary contextual control for selecting attack replay scenarios without
 * cluttering primary application focus.
 */
export const ContextControls: React.FC<{
  selectedScenario: string;
  availableScenarios: readonly { scenario_id: string; display_name: string }[];
  onSelectScenario: (id: string) => void;
  disabled: boolean;
}> = ({ selectedScenario, availableScenarios, onSelectScenario, disabled }) => {
  return (
    <div className="hidden md:flex items-center gap-1.5 px-3 py-1 rounded-full bg-black/40 border border-white/10 text-xs font-mono shrink-0">
      <span className="text-zinc-500 text-[10px] uppercase tracking-wider font-semibold">
        SCENARIO:
      </span>
      <select
        id="scenario-selector"
        value={selectedScenario}
        onChange={(e) => onSelectScenario(e.target.value)}
        disabled={disabled}
        data-cursor="interactive"
        className="bg-transparent text-[#F0C808] text-xs font-mono focus:outline-none cursor-pointer max-w-[180px] lg:max-w-[220px] truncate disabled:opacity-50 disabled:cursor-not-allowed"
        title="Select data-backed attack scenario to replay"
      >
        {availableScenarios.length > 0 ? (
          availableScenarios.map((s) => (
            <option key={s.scenario_id} value={s.scenario_id} className="bg-[#121214] text-white">
              {s.display_name}
            </option>
          ))
        ) : (
          <>
            <option value="scenario_dos_flooding" className="bg-[#121214] text-white">
              DoS Connection Flood (Thu)
            </option>
            <option value="scenario_recon" className="bg-[#121214] text-white">
              Reconnaissance / Scan (Thu)
            </option>
            <option value="scenario_volumetric_surge" className="bg-[#121214] text-white">
              Volumetric Traffic Surge (Wed)
            </option>
            <option value="scenario_safety_boundary" className="bg-[#121214] text-white">
              Safety Boundary Saturation (Wed)
            </option>
          </>
        )}
      </select>
    </div>
  );
};

/**
 * ── Subcomponent 3: Demo Playback Controls ───────────────────────────────────
 * Secondary utility controls: START/PAUSE/RESUME, STEP forward, RESET, and step counter.
 */
export const DemoControls: React.FC<{
  status: string;
  totalSteps: number;
  currentStep?: number;
  onStart: () => void;
  onPause: () => void;
  onResume: () => void;
  onStep: () => void;
  onReset: () => void;
}> = ({ status, totalSteps, currentStep, onStart, onPause, onResume, onStep, onReset }) => {
  const isRunning = status === 'RUNNING';
  const isPaused = status === 'PAUSED';

  const stepFormatted = currentStep !== undefined
    ? `${String(currentStep).padStart(2, '0')}/${String(totalSteps).padStart(2, '0')}`
    : `00/${totalSteps}`;

  return (
    <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-black/40 border border-white/10 font-mono text-xs shrink-0">
      {/* Primary Action Button */}
      {isRunning ? (
        <button
          id="pause-demo-btn"
          onClick={onPause}
          data-cursor="interactive"
          className="bg-[#F0C808] text-black hover:bg-[#FFE14C] px-3 py-0.5 rounded-full font-bold uppercase transition-colors text-[11px]"
          title="Pause demo replay"
        >
          ⏸ PAUSE
        </button>
      ) : isPaused ? (
        <OrbitText
          id="resume-demo-btn"
          onClick={onResume}
          title="Resume demo replay"
          className="text-[11px] px-2.5 py-0.5"
        >
          <span>▶ RESUME</span>
        </OrbitText>
      ) : (
        <OrbitText
          id="start-demo-btn"
          onClick={onStart}
          title="Start deterministic demo replay"
          className="text-[11px] px-2.5 py-0.5"
        >
          <span>▶ START</span>
        </OrbitText>
      )}

      {/* Secondary Controls */}
      <TraceText
        id="step-demo-btn"
        onClick={onStep}
        title="Single logical step forward"
        className="px-2.5 py-0.5 text-[11px] text-zinc-400 hover:text-white rounded-full"
      >
        <span>⏭ STEP</span>
      </TraceText>

      <button
        id="reset-demo-btn"
        onClick={onReset}
        data-cursor="interactive"
        title="Reset scenario to IDLE"
        className="px-2 py-0.5 text-[11px] text-zinc-500 hover:text-red-400 transition-colors rounded-full hover:bg-white/5 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-red-400"
      >
        ↺ RESET
      </button>

      {/* Informational Step Counter */}
      <span className="hidden sm:inline-flex items-center px-2 py-0.5 rounded-full bg-white/[0.04] text-[11px] text-zinc-400 border border-white/5">
        STEP: <strong className="ml-1 text-white">{stepFormatted}</strong>
      </span>
    </div>
  );
};

/**
 * ── Canonical Top Navigation Shell: DefensePipelineNav ───────────────────────
 * CodeFronts SN-05 Floating Glass Pill Sticky Navbar.
 *
 * Single authoritative architecture:
 * - The left-side slide-out drawer owns the 6 pipeline stages (01 to 06).
 * - The top floating glass pill owns application identity, menu trigger,
 *   and contextual secondary controls with generous, intentional whitespace in between.
 */
export const DefensePipelineNav: React.FC<DefensePipelineNavProps> = ({
  selectedScenario,
  availableScenarios,
  onSelectScenario,
  demoStatus,
  currentStepIndex,
  onStartDemo,
  onPauseDemo,
  onResumeDemo,
  onStepDemo,
  onResetDemo,
  connectionState,
  isLive,
  executionMode,
  riskScore,
  className = '',
}) => {
  return (
    <header
      className={`sn-glass-pill ${className}`}
      role="banner"
      aria-label="Defense Control Centre application header"
    >
      {/* 1. Left: Menu Trigger & Application Identity */}
      <DefenseIdentity />

      {/* 2. Center: Intentional Whitespace for Breathing Room */}
      <div className="flex-1 min-w-[20px]" aria-hidden="true" />

      {/* 3. Right: Secondary Contextual Controls & Demo Utilities */}
      <div className="flex items-center gap-2 shrink-0">
        {executionMode !== 'LIVE_PACKET_CAPTURE' && (
          <ContextControls
            selectedScenario={selectedScenario}
            availableScenarios={availableScenarios}
            onSelectScenario={onSelectScenario}
            disabled={demoStatus.status === 'RUNNING' || demoStatus.status === 'PAUSED'}
          />
        )}

        <DemoControls
          status={demoStatus.status}
          totalSteps={demoStatus.total_steps}
          currentStep={currentStepIndex}
          onStart={onStartDemo}
          onPause={onPauseDemo}
          onResume={onResumeDemo}
          onStep={onStepDemo}
          onReset={onResetDemo}
        />

        {/* Status Beacon (Large / Ultra-wide screens) */}
        <div className="hidden xl:flex items-center gap-2 border border-white/10 px-3 py-1 rounded-full bg-black/40 font-mono text-[11px] text-zinc-400">
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              isLive ? 'bg-[#F0C808] animate-pulse shadow-[0_0_6px_#F0C808]' : 'bg-zinc-600'
            }`}
          />
          <span>{isLive ? 'LIVE' : connectionState}</span>
          <span className="text-zinc-700">|</span>
          <span className="text-[#F0C808] font-semibold">L-5</span>
          {riskScore !== undefined && (
            <>
              <span className="text-zinc-700">|</span>
              <span
                className={`px-1.5 py-0.5 rounded-full text-[9px] font-bold ${
                  riskScore > 0.75
                    ? 'text-red-400 bg-red-500/20'
                    : riskScore > 0.4
                    ? 'text-[#F0C808] bg-[#F0C808]/20'
                    : 'text-emerald-400 bg-emerald-500/20'
                }`}
              >
                {(riskScore * 100).toFixed(0)}%
              </span>
            </>
          )}
        </div>
      </div>
    </header>
  );
};
