import React, { useEffect } from 'react';
import { Outlet, NavLink, useLocation } from 'react-router-dom';
import { useRuntimeStore } from '../../store/useRuntimeStore';
import { useControlCenterStore } from '../../store/useControlCenterStore';
import { DefensePipelineNav } from './DefensePipelineNav';
import { DefensePipelineDrawer, AUTHORITATIVE_PIPELINE_STAGES } from './DefensePipelineDrawer';
import { GlassSecurityOverlay } from '../common/GlassSecurityOverlay';

/**
 * Pipeline stage definitions matching the 6-stage Defense Pipeline.
 */
const PIPELINE_STAGES = AUTHORITATIVE_PIPELINE_STAGES;

function getStageIndex(pathname: string): number {
  const idx = PIPELINE_STAGES.findIndex((s) => pathname.startsWith(s.path));
  return idx >= 0 ? idx : 0;
}

function getAdjacentPaths(pathname: string) {
  const idx = getStageIndex(pathname);
  return {
    prev: idx > 0 ? PIPELINE_STAGES[idx - 1] : null,
    current: PIPELINE_STAGES[idx],
    next: idx < PIPELINE_STAGES.length - 1 ? PIPELINE_STAGES[idx + 1] : null,
  };
}

export const PipelineLayout: React.FC = () => {
  const {
    initRuntime,
    connectionState,
    demoStatus,
    snapshot,
    startDemo,
    pauseDemo,
    resumeDemo,
    stepDemo,
    resetDemo,
    selectedScenario,
    setSelectedScenario,
    availableScenarios,
  } = useRuntimeStore();
  const { isCommandPaletteOpen, setCommandPaletteOpen } = useControlCenterStore();
  const location = useLocation();
  const { prev, next } = getAdjacentPaths(location.pathname);

  useEffect(() => {
    initRuntime();
  }, []);

  // Keyboard shortcut: Ctrl+K for command palette
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setCommandPaletteOpen(!isCommandPaletteOpen);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isCommandPaletteOpen]);

  const riskScore = snapshot.event?.current_risk_score;
  const executionMode = demoStatus.execution_mode || 'DEMO';
  const isLive = connectionState === 'CONNECTED';

  return (
    <div className="bg-[#000001] text-white min-h-screen flex flex-col antialiased selection:bg-[#F0C808] selection:text-black">
      {/* ── Checkbox-Hack Toggle Engine ── */}
      <input type="checkbox" id="pipeline-nav-toggle" />

      {/* ── Backdrop Overlay ── */}
      <label htmlFor="pipeline-nav-toggle" className="pipeline-drawer-overlay" aria-label="Close menu" />

      {/* ── Slide-Out Drawer Navigation (CodeFronts SM-17 Compact Glass Dock) ── */}
      <DefensePipelineDrawer
        selectedScenario={selectedScenario}
        setSelectedScenario={setSelectedScenario}
        availableScenarios={availableScenarios}
        isScenarioDisabled={demoStatus.status === 'RUNNING' || demoStatus.status === 'PAUSED'}
      />

      {/* FLOATING GLASS PILL NAVBAR (CODEFRONTS SN-05) */}
      <div className="fixed top-3.5 left-0 md:left-[84px] right-0 z-40 pointer-events-none flex justify-center px-3 sm:px-6">
        <div className="w-full max-w-[1400px] pointer-events-auto">
          <DefensePipelineNav
            stages={PIPELINE_STAGES}
            selectedScenario={selectedScenario}
            availableScenarios={availableScenarios}
            onSelectScenario={setSelectedScenario}
            demoStatus={demoStatus}
            currentStepIndex={snapshot.event?.step_index}
            onStartDemo={() => startDemo(selectedScenario, 1.0)}
            onPauseDemo={() => pauseDemo()}
            onResumeDemo={() => resumeDemo()}
            onStepDemo={() => stepDemo()}
            onResetDemo={() => resetDemo()}
            connectionState={connectionState}
            isLive={isLive}
            executionMode={executionMode}
            riskScore={riskScore}
          />
        </div>
      </div>

      {/* REAL-TIME SECURITY EVENT OVERLAY (CODEFRONTS GLZ-15) */}
      <GlassSecurityOverlay />

      {/* WORKSPACE BODY (EXPANDABLE DOCK ARCHITECTURE) */}
      <div className="flex-1 flex flex-col overflow-hidden md:pl-[84px] transition-all">
        {/* MAIN CONTENT AREA */}
        <main className="flex-1 overflow-y-auto custom-scrollbar flex flex-col pt-24 pb-4">
          <div className="flex-1 px-4 sm:px-8 lg:px-12 pt-2 pb-8 max-w-7xl mx-auto w-full flex flex-col justify-between space-y-8">
            <Outlet />
          </div>

          {/* FOOTER NAVIGATION */}
          <footer className="border-t border-[#27272A]/60 px-8 py-4 flex items-center justify-between font-mono shrink-0">
            {prev ? (
              <NavLink
                to={prev.path}
                className="text-[#71717A] hover:text-white transition-colors flex items-center gap-2 text-xs px-4 py-2 rounded-full border border-[#27272A] bg-[#080808] hover:border-[#F0C808]"
              >
                <span>←</span>
                <span className="tracking-wider uppercase">
                  BACK TO STAGE {prev.id}: {prev.label}
                </span>
              </NavLink>
            ) : (
              <div />
            )}

            {next && (
              <div className="hidden sm:flex items-center gap-2 text-xs text-[#71717A]">
                <span className="w-2 h-2 rounded-full bg-[#F0C808] animate-ping" />
                <span className="text-[#A1A1AA] uppercase tracking-wider">
                  READY FOR {next.verb}
                </span>
              </div>
            )}

            {next ? (
              <NavLink
                to={next.path}
                className="px-8 py-3 rounded-full bg-[#F0C808] hover:bg-[#FFE14C] text-black font-bold text-sm tracking-wider flex items-center gap-3 transition-all shadow-[0_0_15px_rgba(240,200,8,0.25)] hover:shadow-[0_0_20px_rgba(240,200,8,0.45)] focus:outline-none"
              >
                <span>PROCEED TO {next.label}</span>
                <span className="font-bold">→</span>
              </NavLink>
            ) : (
              <div className="text-xs text-[#F0C808] font-bold px-4 py-2 rounded-full bg-[#F0C808]/10 border border-[#F0C808]/30">
                PIPELINE COMPLETE
              </div>
            )}
          </footer>
        </main>
      </div>
    </div>
  );
};
