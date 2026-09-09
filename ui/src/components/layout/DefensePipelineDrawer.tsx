import React, { useRef, useEffect, useCallback } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity,
  TrendingUp,
  SlidersHorizontal,
  UserCheck,
  CheckCircle2,
  History,
  Shield,
  X,
  ArrowLeft,
} from 'lucide-react';
import { MetallicShimmerText } from '../common/MetallicShimmerText';

export interface PipelineStageConfig {
  readonly id: string;
  readonly label: string;
  readonly verb: string;
  readonly path: string;
}

export const AUTHORITATIVE_PIPELINE_STAGES: readonly PipelineStageConfig[] = [
  { id: '01', label: 'NETWORK STATE', verb: 'OBSERVE', path: '/pipeline/observe' },
  { id: '02', label: 'TRAJECTORY', verb: 'PREDICT', path: '/pipeline/predict' },
  { id: '03', label: 'INTERVENTION', verb: 'SIMULATE', path: '/pipeline/simulate' },
  { id: '04', label: 'APPROVAL', verb: 'APPROVE', path: '/pipeline/approve' },
  { id: '05', label: 'VERIFICATION', verb: 'VERIFY', path: '/pipeline/verify' },
  { id: '06', label: 'AUDIT & TRACE', verb: 'TRACE', path: '/pipeline/trace' },
] as const;

// Semantic icon map for each pipeline stage (18-20px, consistent stroke weight)
const STAGE_ICONS: Record<string, React.FC<{ className?: string }>> = {
  '01': ({ className }) => <Activity size={18} strokeWidth={1.8} className={className} />,
  '02': ({ className }) => <TrendingUp size={18} strokeWidth={1.8} className={className} />,
  '03': ({ className }) => <SlidersHorizontal size={18} strokeWidth={1.8} className={className} />,
  '04': ({ className }) => <UserCheck size={18} strokeWidth={1.8} className={className} />,
  '05': ({ className }) => <CheckCircle2 size={18} strokeWidth={1.8} className={className} />,
  '06': ({ className }) => <History size={18} strokeWidth={1.8} className={className} />,
};

interface DefensePipelineDrawerProps {
  selectedScenario?: string;
  setSelectedScenario?: (scenario: string) => void;
  availableScenarios?: Array<{ scenario_id: string; display_name: string }>;
  isScenarioDisabled?: boolean;
}

export const DefensePipelineDrawer: React.FC<DefensePipelineDrawerProps> = ({
  selectedScenario,
  setSelectedScenario,
  availableScenarios = [],
  isScenarioDisabled = false,
}) => {
  const location = useLocation();
  const navigate = useNavigate();

  const containerRef = useRef<HTMLDivElement>(null);
  const highlightRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<Map<string, HTMLAnchorElement>>(new Map());

  // Close the drawer by unchecking the checkbox
  const closeDrawer = useCallback(() => {
    const toggle = document.getElementById('pipeline-nav-toggle') as HTMLInputElement | null;
    if (toggle) toggle.checked = false;
  }, []);

  // Compute active stage based on current location
  const currentActiveStage =
    AUTHORITATIVE_PIPELINE_STAGES.find((s) => location.pathname.startsWith(s.path)) ||
    AUTHORITATIVE_PIPELINE_STAGES[0];

  // Move the single sliding highlight behind the target stage element
  const moveHighlight = useCallback((stagePath: string) => {
    const targetEl = itemRefs.current.get(stagePath);
    const containerEl = containerRef.current;
    const highlightEl = highlightRef.current;

    if (!targetEl || !containerEl || !highlightEl) return;

    const containerRect = containerEl.getBoundingClientRect();
    const targetRect = targetEl.getBoundingClientRect();
    const y = targetRect.top - containerRect.top;
    const h = targetRect.height;

    highlightEl.style.transform = `translateY(${y}px)`;
    highlightEl.style.height = `${h}px`;
    highlightEl.style.opacity = '1';
  }, []);

  // Synchronize highlight with current active stage
  const syncToActive = useCallback(() => {
    requestAnimationFrame(() => {
      moveHighlight(currentActiveStage.path);
    });
  }, [currentActiveStage.path, moveHighlight]);

  useEffect(() => {
    syncToActive();
    const t1 = setTimeout(syncToActive, 50);
    const t2 = setTimeout(syncToActive, 200);

    const toggle = document.getElementById('pipeline-nav-toggle') as HTMLInputElement | null;
    const handleToggle = () => {
      if (toggle?.checked) {
        setTimeout(syncToActive, 60);
        setTimeout(syncToActive, 200);
        setTimeout(syncToActive, 450);
      }
    };

    toggle?.addEventListener('change', handleToggle);
    window.addEventListener('resize', syncToActive);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      toggle?.removeEventListener('change', handleToggle);
      window.removeEventListener('resize', syncToActive);
    };
  }, [location.pathname, syncToActive]);

  return (
    <nav
      className="pipeline-drawer-nav font-mono select-none"
      aria-label="Defense pipeline"
    >
      {/* ── Compact Header (Collapsed: Shield icon only | Expanded: Full title + close) ── */}
      <div className="h-14 px-3.5 border-b border-white/[0.08] flex items-center justify-between shrink-0 overflow-hidden">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-[#F0C808]/10 border border-[#F0C808]/30 flex items-center justify-center text-[#F0C808] shrink-0">
            <Shield size={16} strokeWidth={2.2} />
          </div>
          <div className="sm17-header-title text-xs uppercase tracking-widest font-bold font-mono">
            <MetallicShimmerText as="span" variant="gold" mode="sweep">
              DEFENSE PIPELINE
            </MetallicShimmerText>
          </div>
        </div>

        {/* Compact [X] close button */}
        <label
          htmlFor="pipeline-nav-toggle"
          role="button"
          tabIndex={0}
          aria-label="Close defense pipeline"
          className="sm17-header-close w-7 h-7 rounded-full flex items-center justify-center text-[#A1A1AA] hover:text-white hover:bg-white/[0.08] border border-white/10 transition-colors cursor-pointer shrink-0 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#F0C808]"
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              closeDrawer();
            }
          }}
        >
          <X size={15} strokeWidth={2} />
        </label>
      </div>

      {/* ── Body Area ── */}
      <div className="flex-1 overflow-y-auto px-2 py-3 flex flex-col custom-scrollbar overflow-x-hidden">
        {/* Quiet section label (Collapsed: hidden | Expanded: fades in) */}
        <div className="sm17-section-label px-3 pt-1 pb-1 text-[10px] text-[#71717A] uppercase tracking-widest font-semibold font-mono">
          PIPELINE
        </div>

        {/* ── Stage List with Single Shared Sliding Active Highlight ── */}
        <div
          ref={containerRef}
          className="relative flex flex-col gap-1 isolation-isolate"
          onPointerLeave={() => syncToActive()}
          onBlur={(e) => {
            if (!containerRef.current?.contains(e.relatedTarget as Node)) {
              syncToActive();
            }
          }}
        >
          {/* SM-17 Sliding Specular Active Highlight */}
          <div
            ref={highlightRef}
            className="sm17-highlight"
            aria-hidden="true"
            style={{ opacity: 0 }}
          />

          {AUTHORITATIVE_PIPELINE_STAGES.map((stage) => {
            const isActive = location.pathname.startsWith(stage.path);
            const StageIcon = STAGE_ICONS[stage.id] || Activity;

            return (
              <NavLink
                key={stage.id}
                to={stage.path}
                ref={(el) => {
                  if (el) itemRefs.current.set(stage.path, el);
                  else itemRefs.current.delete(stage.path);
                }}
                aria-current={isActive ? 'page' : undefined}
                onClick={closeDrawer}
                onPointerEnter={() => moveHighlight(stage.path)}
                onFocus={() => moveHighlight(stage.path)}
                className={`group relative z-[1] flex items-center h-[44px] px-3 rounded-xl transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#F0C808] overflow-hidden ${
                  isActive ? 'text-white' : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                {/* Left: Icon (always visible, centered in 44px item when collapsed) */}
                <div className="w-5 h-5 flex items-center justify-center shrink-0">
                  <StageIcon
                    className={`transition-colors ${
                      isActive ? 'text-[#F0C808]' : 'text-[#71717A] group-hover:text-white'
                    }`}
                  />
                </div>

                {/* Revealed on expansion: Number + Name + Verb */}
                <div className="sm17-label-wrapper flex items-center justify-between flex-1 min-w-0 pl-3">
                  <div className="flex items-center gap-2 min-w-0 pr-2 truncate">
                    <span
                      className={`text-[11px] font-mono tracking-wider shrink-0 transition-colors ${
                        isActive ? 'text-[#F0C808] font-bold' : 'text-[#71717A]'
                      }`}
                    >
                      {stage.id}
                    </span>
                    <span
                      className={`text-xs font-mono tracking-wide truncate ${
                        isActive ? 'font-bold text-white' : 'font-medium text-[#D4D4D8]'
                      }`}
                    >
                      {stage.label}
                    </span>
                  </div>

                  <span
                    className={`text-[9.5px] font-mono tracking-widest uppercase shrink-0 transition-colors ${
                      isActive
                        ? 'text-[#F0C808] font-bold'
                        : 'text-[#71717A]'
                    }`}
                  >
                    {stage.verb}
                  </span>
                </div>
              </NavLink>
            );
          })}
        </div>

        {/* Divider */}
        <div className="my-2.5 border-t border-white/[0.08] mx-1" />

        {/* Return to Landing Page */}
        <button
          type="button"
          onClick={() => {
            closeDrawer();
            navigate('/');
          }}
          className="group flex items-center h-[40px] px-3 text-xs font-mono text-[#A1A1AA] hover:text-white rounded-xl hover:bg-white/[0.05] transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#F0C808] overflow-hidden"
          title="Return to Landing Page"
        >
          <div className="w-5 h-5 flex items-center justify-center shrink-0">
            <ArrowLeft
              size={16}
              strokeWidth={1.8}
              className="text-[#71717A] group-hover:text-[#F0C808] group-hover:-translate-x-0.5 transition-all"
            />
          </div>
          <span className="sm17-label-wrapper pl-3 tracking-wide truncate">
            RETURN TO LANDING
          </span>
        </button>

        {/* Mobile Scenario Selector inside drawer */}
        {setSelectedScenario && (
          <div className="md:hidden sm17-label-wrapper pt-2 pb-1 overflow-hidden flex flex-col">
            <div className="text-[10px] text-[#71717A] uppercase tracking-wider pb-1 font-semibold font-mono">
              ACTIVE SCENARIO
            </div>
            <select
              value={selectedScenario}
              onChange={(e) => setSelectedScenario(e.target.value)}
              disabled={isScenarioDisabled}
              className="w-full bg-[#121214] text-[#F0C808] text-xs font-mono px-2.5 py-1.5 rounded-xl border border-white/10 focus:outline-none cursor-pointer"
            >
              {availableScenarios.length > 0 ? (
                availableScenarios.map((s) => (
                  <option key={s.scenario_id} value={s.scenario_id}>
                    {s.display_name}
                  </option>
                ))
              ) : (
                <>
                  <option value="scenario_dos_flooding">DoS Connection Flood (Thu)</option>
                  <option value="scenario_recon">Reconnaissance / Scan (Thu)</option>
                  <option value="scenario_volumetric_surge">Volumetric Traffic Surge (Wed)</option>
                  <option value="scenario_safety_boundary">Safety Boundary Saturation (Wed)</option>
                </>
              )}
            </select>
          </div>
        )}

        {/* Flexible empty space pushing operator to bottom */}
        <div className="flex-1 min-h-[16px]" />
      </div>

      {/* ── Compact Operator Panel at Bottom ── */}
      <div className="p-2 m-2 rounded-xl border border-white/[0.08] bg-white/[0.02] flex items-center gap-2.5 shrink-0 overflow-hidden">
        <div
          className="w-8 h-8 rounded-full bg-[#141416] border border-[#F0C808]/40 flex items-center justify-center font-bold text-[10px] font-mono text-[#F0C808] shadow-[0_0_8px_rgba(240,200,8,0.2)] shrink-0"
          title="OPERATOR_01 (CLEARANCE L-5 · ACTIVE)"
        >
          OP
        </div>
        <div className="sm17-operator-details min-w-0 flex-1">
          <div className="text-xs font-bold font-mono text-white leading-tight truncate">
            OPERATOR_01
          </div>
          <div className="text-[10px] font-mono text-[#71717A] leading-tight tracking-wider truncate flex items-center gap-1.5 mt-0.5">
            <span>CLEARANCE L-5</span>
            <span className="text-[#52525B]">·</span>
            <span className="inline-flex items-center gap-1 text-[#10B981]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]" />
              ACTIVE
            </span>
          </div>
        </div>
      </div>
    </nav>
  );
};
