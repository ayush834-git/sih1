import React, { useState } from 'react';
import { useControlCenterStore } from '../store/useControlCenterStore';
import { useRuntimeStore } from '../store/useRuntimeStore';
import { TIMELINE_MARKERS } from '../data/mockData';
import type { PathTraceStage } from '../types/controlCenter';
import { useNavigate } from 'react-router-dom';

export const InvestigationWorkspacePage: React.FC = () => {
  const {
    activeCase,
    escalateCase,
    closeCase,
    setSelectedEvidenceId,
    graphDepth,
    setGraphDepth,
    selectedFilterChip,
    setSelectedFilterChip,
    activePathStage,
    setActivePathStage,
  } = useControlCenterStore();

  const { snapshot } = useRuntimeStore();
  const liveEvent = snapshot.event;

  const [selectedNodeId, setSelectedNodeId] = useState<string>('node-domain');
  const [focusedMarkerId, setFocusedMarkerId] = useState<string>('tm-3');
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [timelineRange, setTimelineRange] = useState<'1H' | '24H' | '7D'>('7D');
  const [activeSignalFilter, setActiveSignalFilter] = useState<'OBSERVATION' | 'CORRELATION' | 'IDENTITY'>('CORRELATION');
  const [notification, setNotification] = useState<string | null>(null);
  const [activeProvenanceStep, setActiveProvenanceStep] = useState<number>(3);
  const navigate = useNavigate();

  const handleEscalate = () => {
    escalateCase(activeCase.id);
    setNotification('CASE ESCALATED TO SENIOR INCIDENT COMMANDER');
    setTimeout(() => setNotification(null), 3000);
  };

  const handleClose = () => {
    closeCase(activeCase.id);
    setNotification('CASE CLOSED & ARCHIVED WITH AUDIT SIGNATURE');
    setTimeout(() => setNotification(null), 3000);
  };

  const handleExport = () => {
    setNotification('FORENSIC DOSSIER EXPORTED (.PDF / .JSON)');
    setTimeout(() => setNotification(null), 3000);
  };

  const handleVerifyDecision = () => {
    setNotification('RELATIONSHIP VERIFIED AND COMMITTED TO ATTRIBUTION MODEL');
    setTimeout(() => setNotification(null), 3000);
  };

  const handleTraceForward = () => {
    const stages: PathTraceStage[] = ['IDENTITY', 'PGP', 'DOMAIN', 'INFRA'];
    const currentIndex = stages.indexOf(activePathStage);
    if (currentIndex < stages.length - 1) {
      setActivePathStage(stages[currentIndex + 1]);
    }
  };

  const handleTraceBack = () => {
    const stages: PathTraceStage[] = ['IDENTITY', 'PGP', 'DOMAIN', 'INFRA'];
    const currentIndex = stages.indexOf(activePathStage);
    if (currentIndex > 0) {
      setActivePathStage(stages[currentIndex - 1]);
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#000001] text-white overflow-hidden relative">
      {/* Toast Notification */}
      {notification && (
        <div className="absolute top-4 right-8 z-50 bg-[#111111] border border-[#F0C808] text-[#F0C808] px-4 py-2 font-label-caps text-label-caps flex items-center gap-2 shadow-2xl animate-fade-in">
          <span className="material-symbols-outlined text-[18px]">verified</span>
          <span>{notification}</span>
        </div>
      )}

      {/* Global Context Breadcrumbs */}
      <div className="bg-[#0A0A0A] border-b border-[#262626] px-8 py-2 flex items-center gap-4 overflow-x-auto shrink-0 font-metadata text-metadata">
        <span className="text-[#F0C808] font-bold">{activeCase.id}</span>
        <span className="text-[#353535] text-[10px]">//</span>
        <span className="text-[#8e9192]">
          SUBJECT: <span className="text-white font-bold">{activeCase.subject}</span>
        </span>
        <span className="text-[#353535] text-[10px]">//</span>
        <span className="text-[#8e9192]">
          TARGET: <span className="text-white font-bold">{activeCase.targetVector || 'svc-api'}</span>
        </span>
        <span className="text-[#353535] text-[10px]">//</span>
        <span className="text-[#8e9192]">
          CONFIDENCE:{' '}
          <span className="text-[#F0C808] font-bold">
            {liveEvent ? `${Math.round(liveEvent.stage_confidence * 100)}%` : `${activeCase.attributionConfidence}%`}
          </span>
        </span>
        <span className="text-[#353535] text-[10px]">//</span>
        <span className="text-[#8e9192]">
          STAGE:{' '}
          <span className="text-white font-bold">
            {liveEvent ? liveEvent.primary_stage : 'RECONNAISSANCE'}
          </span>
        </span>
      </div>

      {/* Main Container */}
      <div className="flex-1 overflow-y-auto bg-[#262626] p-[1px] flex flex-col gap-[1px]">
        {/* MODULE 1: Header / Title Block */}
        <section className="bg-[#080808] p-8 flex justify-between items-end shrink-0 border-b border-[#262626]">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2 text-[#c6c6c6]">
              <span className="material-symbols-outlined text-[16px]">folder_open</span>
              <span className="font-label-caps text-label-caps uppercase">ACTIVE INVESTIGATION</span>
            </div>
            <h2 className="font-display-lg text-display-lg text-white leading-none uppercase tracking-tighter text-[64px]">
              {activeCase.id}
            </h2>
            <div className="flex items-center gap-8 mt-2">
              <div className="flex items-center gap-2">
                <span className="font-metadata text-metadata text-[#8e9192] uppercase">SUBJECT:</span>
                <span className="font-label-caps text-label-caps text-white uppercase bg-[#111111] px-2 py-1 border border-[#262626]">
                  {activeCase.subject}
                </span>
              </div>
              {activeCase.status !== 'ACTIVE' && (
                <span className="font-label-caps text-label-caps text-[#F0C808] border border-[#F0C808] px-2 py-0.5">
                  STATUS: {activeCase.status}
                </span>
              )}
            </div>
          </div>

          <div className="flex flex-col items-end gap-6">
            <div className="flex flex-col items-end gap-1 text-right">
              <span className="font-metadata text-metadata text-[#c6c6c6] uppercase">
                {liveEvent ? 'STAGE CONFIDENCE' : 'ATTRIBUTION CONFIDENCE'}
              </span>
              <span className="font-headline-lg text-headline-lg text-white leading-none text-[36px]">
                {liveEvent ? `${Math.round(liveEvent.stage_confidence * 100)}%` : `${activeCase.attributionConfidence}%`}
              </span>
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleExport}
                className="font-label-caps text-label-caps text-white uppercase border border-[#262626] px-4 py-2 hover:border-white hover:bg-[#181818] transition-colors cursor-pointer"
              >
                EXPORT
              </button>
              <button
                onClick={handleEscalate}
                className="font-label-caps text-label-caps text-white uppercase border border-[#262626] px-4 py-2 hover:border-white hover:bg-[#181818] transition-colors cursor-pointer"
              >
                ESCALATE
              </button>
              <button
                onClick={handleClose}
                className="font-label-caps text-label-caps text-black bg-white uppercase px-4 py-2 hover:bg-[#c6c6c6] transition-colors font-bold cursor-pointer"
              >
                CLOSE CASE
              </button>
            </div>
          </div>
        </section>

        {/* MODULE 2 & 3 Row: Canvas and Advanced Multi-Stage Controller */}
        <section className="flex flex-1 gap-[1px] min-h-[520px]">
          {/* MODULE 2: Relationship Graph Canvas */}
          <div className="bg-[#080808] flex-1 relative overflow-hidden flex items-center justify-center group border border-transparent hover:border-[#262626] transition-colors">
            {/* Top Canvas Bar */}
            <div className="absolute top-4 left-4 flex items-center gap-2 z-10">
              <span className="material-symbols-outlined text-[#c6c6c6] text-[16px]">hub</span>
              <span className="font-label-caps text-label-caps text-[#c6c6c6] uppercase tracking-widest">
                RELATIONSHIP GRAPH CANVAS
              </span>
              <span className="font-metadata text-[10px] text-[#FFD60A] bg-[#111111] border border-[#333333] px-2 py-0.5 ml-2">
                [STRUCTURAL BASELINE DIAGRAM]
              </span>
            </div>
            <div className="absolute top-4 right-4 flex gap-2 z-10">
              <button
                onClick={() => setZoomLevel((z) => Math.min(z + 0.2, 1.8))}
                title="Zoom In"
                className="p-1 border border-[#262626] text-[#c6c6c6] hover:text-white hover:border-white bg-[#080808] cursor-pointer"
              >
                <span className="material-symbols-outlined text-[16px]">zoom_in</span>
              </button>
              <button
                onClick={() => setZoomLevel((z) => Math.max(z - 0.2, 0.6))}
                title="Zoom Out"
                className="p-1 border border-[#262626] text-[#c6c6c6] hover:text-white hover:border-white bg-[#080808] cursor-pointer"
              >
                <span className="material-symbols-outlined text-[16px]">zoom_out</span>
              </button>
              <button
                onClick={() => setZoomLevel(1)}
                title="Reset View"
                className="p-1 border border-[#262626] text-[#c6c6c6] hover:text-white hover:border-white bg-[#080808] cursor-pointer"
              >
                <span className="material-symbols-outlined text-[16px]">center_focus_strong</span>
              </button>
            </div>

            {/* Expansion Controls (Bottom Left) */}
            <div className="absolute bottom-4 left-4 z-20 flex flex-col gap-2">
              <div className="bg-[#0A0A0A] border border-[#262626] p-3 flex flex-col gap-2 w-48 shadow-2xl">
                <div className="flex justify-between items-center border-b border-[#262626] pb-1">
                  <span className="font-label-caps text-[10px] text-[#c6c6c6]">EXPANSION CONTROL</span>
                  <span className="font-metadata text-[9px] text-[#F0C808] font-bold">DEPTH: {graphDepth}</span>
                </div>
                <div className="grid grid-cols-2 gap-1 font-metadata text-[9px]">
                  <span className="text-[#8e9192]">REL: 14</span>
                  <span className="text-[#8e9192]">NEW: 06</span>
                </div>
                <div className="flex gap-1 mt-1">
                  <button
                    onClick={() => setGraphDepth(2)}
                    className={`flex-1 border py-1 text-[9px] font-label-caps transition-colors cursor-pointer ${
                      graphDepth === 2 ? 'bg-white text-black font-bold border-white' : 'border-[#262626] text-[#c6c6c6] hover:bg-[#181818]'
                    }`}
                  >
                    EXPAND
                  </button>
                  <button
                    onClick={() => setGraphDepth(1)}
                    className={`flex-1 border py-1 text-[9px] font-label-caps transition-colors cursor-pointer ${
                      graphDepth === 1 ? 'bg-white text-black font-bold border-white' : 'border-[#262626] text-[#c6c6c6] hover:bg-[#181818]'
                    }`}
                  >
                    COLLAPSE
                  </button>
                </div>
              </div>

              {/* Filter Chips */}
              <div className="bg-[#0A0A0A] border border-[#262626] p-1 flex gap-1">
                {(['ID', 'INFRA', 'BEH', 'CRYP'] as const).map((chip) => (
                  <button
                    key={chip}
                    onClick={() => setSelectedFilterChip(chip)}
                    className={`px-2 py-1 text-[9px] font-label-caps transition-colors cursor-pointer ${
                      selectedFilterChip === chip
                        ? 'bg-white text-black font-bold'
                        : 'border border-[#262626] text-[#8e9192] hover:text-white'
                    }`}
                  >
                    {chip}
                  </button>
                ))}
              </div>
            </div>

            {/* Grid Pattern */}
            <div
              className="w-full h-full absolute inset-0 opacity-10"
              style={{
                backgroundImage: 'radial-gradient(#444748 1px, transparent 1px)',
                backgroundSize: '24px 24px',
              }}
            ></div>

            {/* SVG Lines for Active & Subdued Connections */}
            <svg
              className="absolute inset-0 w-full h-full pointer-events-none z-0"
              style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'center center', transition: 'transform 0.2s ease-out' }}
            >
              {/* Active Golden Path Edges */}
              <line stroke="#F0C808" strokeWidth="1.5" x1="25%" x2="50%" y1="50%" y2="50%"></line>
              <line stroke="#F0C808" strokeWidth="1.5" x1="50%" x2="75%" y1="50%" y2="35%"></line>
              <line stroke="#F0C808" strokeWidth="1.5" x1="75%" x2="90%" y1="35%" y2="50%"></line>

              {/* Second Degree & Subdued Edges */}
              {graphDepth >= 2 && (
                <>
                  <line className="dash-line opacity-40" stroke="#444748" strokeWidth="1" x1="25%" x2="15%" y1="50%" y2="25%"></line>
                  <line className="dash-interrupted opacity-40" stroke="#444748" strokeWidth="1" x1="75%" x2="85%" y1="35%" y2="15%"></line>
                  <line className="dash-interrupted opacity-40" stroke="#444748" strokeWidth="1" x1="75%" x2="85%" y1="35%" y2="35%"></line>
                </>
              )}
            </svg>

            {/* Graph Nodes */}
            <div
              className="w-full h-full relative"
              style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'center center', transition: 'transform 0.2s ease-out' }}
            >
              {/* Active Node 1: IDENTITY (CIPHERPINE) */}
              <div
                onClick={() => {
                  setSelectedNodeId('node-identity');
                  setActivePathStage('IDENTITY');
                }}
                className={`group absolute top-[50%] left-[25%] transform -translate-x-1/2 -translate-y-1/2 border border-[#F0C808] bg-[#111111] p-3 z-20 w-44 shadow-[0_0_15px_rgba(240,200,8,0.15)] cursor-pointer transition-all ${
                  selectedNodeId === 'node-identity' ? 'scale-105' : ''
                }`}
              >
                <div className="flex items-center gap-2 border-b border-[#262626] pb-1 mb-1">
                  <span className="material-symbols-outlined text-[16px] text-[#F0C808]">person</span>
                  <span className="font-label-caps text-label-caps text-[#F0C808] uppercase">IDENTITY</span>
                </div>
                <p className="font-metadata text-metadata text-white font-bold truncate">CIPHERPINE</p>
              </div>

              {/* Active Node 2: PGP FINGERPRINT */}
              <div
                onClick={() => {
                  setSelectedNodeId('node-pgp');
                  setActivePathStage('PGP');
                  setSelectedEvidenceId('EV-00403');
                }}
                className={`absolute top-[50%] left-[50%] transform -translate-x-1/2 -translate-y-1/2 border border-[#F0C808] bg-[#080808] p-3 z-20 w-48 shadow-[0_0_10px_rgba(240,200,8,0.1)] cursor-pointer transition-all ${
                  selectedNodeId === 'node-pgp' ? 'scale-105' : ''
                }`}
              >
                <div className="flex items-center gap-2 border-b border-[#262626] pb-1 mb-1">
                  <span className="material-symbols-outlined text-[16px] text-[#F0C808]">fingerprint</span>
                  <span className="font-label-caps text-[10px] text-[#F0C808] uppercase">PGP FINGERPRINT</span>
                </div>
                <p className="font-metadata text-[10px] text-white truncate font-bold">A3B4:C5D6:E7F8</p>
              </div>

              {/* Active Node 3: DOMAIN (C9-SECURE.NET) */}
              <div
                onClick={() => {
                  setSelectedNodeId('node-domain');
                  setActivePathStage('DOMAIN');
                  setSelectedEvidenceId('EV-00421');
                }}
                className={`absolute top-[35%] left-[75%] transform -translate-x-1/2 -translate-y-1/2 border border-[#F0C808] bg-[#080808] p-3 z-20 w-48 shadow-[0_0_10px_rgba(240,200,8,0.1)] cursor-pointer transition-all ${
                  selectedNodeId === 'node-domain' ? 'scale-105' : ''
                }`}
              >
                <div className="flex items-center gap-2 border-b border-[#262626] pb-1 mb-1">
                  <span className="material-symbols-outlined text-[16px] text-[#F0C808]">language</span>
                  <span className="font-label-caps text-[10px] text-[#F0C808] uppercase">DOMAIN</span>
                </div>
                <p className="font-metadata text-[10px] text-white truncate font-bold">C9-SECURE.NET</p>
              </div>

              {/* Active Node 4: INFRASTRUCTURE (IP 198.51.100.42) */}
              <div
                onClick={() => {
                  setSelectedNodeId('node-infra');
                  setActivePathStage('INFRA');
                  setSelectedEvidenceId('EV-00421');
                }}
                className={`absolute top-[50%] left-[90%] transform -translate-x-1/2 -translate-y-1/2 border border-[#F0C808] bg-[#080808] p-3 z-20 w-44 shadow-[0_0_10px_rgba(240,200,8,0.1)] cursor-pointer transition-all ${
                  selectedNodeId === 'node-infra' ? 'scale-105' : ''
                }`}
              >
                <div className="flex items-center gap-2 border-b border-[#262626] pb-1 mb-1">
                  <span className="material-symbols-outlined text-[16px] text-[#F0C808]">router</span>
                  <span className="font-label-caps text-[10px] text-[#F0C808] uppercase">INFRASTRUCTURE</span>
                </div>
                <p className="font-metadata text-[10px] text-white truncate font-bold">198.51.100.42</p>
              </div>

              {/* Subdued / Second Degree Nodes */}
              {graphDepth >= 2 && (
                <>
                  <div className="absolute top-[25%] left-[15%] transform -translate-x-1/2 -translate-y-1/2 border border-[#262626] bg-[#080808] p-2 z-0 w-36 opacity-50">
                    <p className="font-metadata text-[9px] text-[#8e9192]">ALIAS: 'DARKPINE'</p>
                  </div>
                  <div className="absolute top-[15%] left-[85%] transform -translate-x-1/2 -translate-y-1/2 border border-[#262626] bg-[#080808] p-2 z-0 w-36 opacity-50">
                    <p className="font-metadata text-[9px] text-[#8e9192]">SSL CERTIFICATE</p>
                  </div>
                  <div className="absolute top-[35%] left-[85%] transform -translate-x-1/2 -translate-y-1/2 border border-[#262626] bg-[#080808] p-2 z-0 w-36 opacity-50">
                    <p className="font-metadata text-[9px] text-[#8e9192]">MAIL SERVER</p>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* MODULE 3: Multi-Stage Path Controller & Forensic Drawer */}
          <aside className="bg-[#080808] w-[450px] shrink-0 flex flex-col z-20 border-l border-[#262626] overflow-y-auto">
            <div className="p-6 flex flex-col h-full gap-6">
              {/* Header */}
              <div className="flex items-center gap-2 border-b border-[#F0C808] pb-2">
                <span className="material-symbols-outlined text-[#F0C808] text-[20px]">account_tree</span>
                <h3 className="font-title-md text-title-md text-[#F0C808] uppercase tracking-wider">
                  MULTI-STAGE PATH CONTROLLER
                </h3>
              </div>

              {/* Path Navigation Strip */}
              <div className="flex gap-2 font-label-caps text-[10px] text-[#8e9192] uppercase border-b border-[#262626] pb-3 overflow-x-auto whitespace-nowrap">
                {(['IDENTITY', 'PGP', 'DOMAIN', 'INFRA'] as PathTraceStage[]).map((stage, idx, arr) => (
                  <React.Fragment key={stage}>
                    <button
                      onClick={() => setActivePathStage(stage)}
                      className={`px-2 py-1 border transition-colors cursor-pointer ${
                        activePathStage === stage
                          ? 'border-[#F0C808] bg-[#111111] text-[#F0C808] font-bold'
                          : 'border-[#262626] text-[#8e9192] hover:text-white'
                      }`}
                    >
                      {stage}
                    </button>
                    {idx < arr.length - 1 && (
                      <span className="material-symbols-outlined text-[12px] self-center text-[#8e9192]">
                        arrow_right_alt
                      </span>
                    )}
                  </React.Fragment>
                ))}
              </div>

              {/* Active Stage Metadata */}
              <div className="flex flex-col gap-2">
                <h4 className="font-label-caps text-label-caps text-[#8e9192] uppercase border-b border-[#262626] pb-1">
                  ACTIVE STAGE METADATA
                </h4>
                <div className="grid grid-cols-2 gap-2 font-metadata text-[10px] mt-1 bg-[#0A0A0A] p-3 border border-[#262626]">
                  <div className="flex flex-col">
                    <span className="text-[#8e9192]">ENTITY NAME:</span>
                    <span className="text-white font-bold">
                      {activePathStage === 'IDENTITY'
                        ? 'CIPHERPINE'
                        : activePathStage === 'PGP'
                        ? 'A3B4:C5D6:E7F8'
                        : activePathStage === 'DOMAIN'
                        ? 'C9-SECURE.NET'
                        : '198.51.100.42'}
                    </span>
                  </div>
                  <div className="flex flex-col">
                    <span className="text-[#8e9192]">TYPE:</span>
                    <span className="text-white">{activePathStage === 'DOMAIN' ? 'Domain' : 'Infrastructure'}</span>
                  </div>
                  <div className="flex flex-col">
                    <span className="text-[#8e9192]">CONFIDENCE:</span>
                    <span className="text-[#F0C808] font-bold">87%</span>
                  </div>
                  <div className="flex flex-col">
                    <span className="text-[#8e9192]">OBSERVATIONS:</span>
                    <span className="text-white">08</span>
                  </div>
                </div>
              </div>

              {/* Analytical Metrics */}
              <div className="flex flex-col gap-2">
                <div className="flex justify-between items-end">
                  <span className="font-label-caps text-label-caps text-[#8e9192] uppercase">PATH CONFIDENCE</span>
                  <span className="font-headline-lg-mobile text-headline-lg-mobile text-[#F0C808] font-bold">87%</span>
                </div>
                <div className="w-full h-1 bg-[#181818]">
                  <div className="h-full bg-[#F0C808] w-[87%]"></div>
                </div>
                <div className="flex justify-between font-metadata text-[9px] mt-1">
                  <span className="text-white font-bold">SUPPORTING: 08</span>
                  <span className="text-[#ffb4ab]">CONFLICTING: 01</span>
                  <span className="text-[#8e9192]">UNRESOLVED: 02</span>
                </div>
              </div>

              {/* Provenance & Forensic Drawer */}
              <div className="flex flex-col border border-[#262626] p-3 bg-[#0A0A0A]">
                <h4 className="font-label-caps text-label-caps text-white uppercase border-b border-[#262626] pb-1 mb-2">
                  PROVENANCE & FORENSICS
                </h4>
                <div className="flex flex-col gap-1 font-metadata text-[10px]">
                  {[
                    `SOURCE: ${liveEvent ? 'PCAP_INGRESS_STREAM' : 'TELEMETRY_FEED_ALPHA'}`,
                    `COLLECTION BASELINE: ${liveEvent?.wall_clock_time || '2026-08-30 14:10:00 UTC'}`,
                    'RAW OBSERVATION: PCAP / FLOW TELEMETRY',
                    'NORMALIZATION: INGEST_GATEWAY_NODE_4',
                    'EXTRACTION: FLOW_RATE, SYN_RATIO, PACKET_LEN',
                    `CORRELATION: ${liveEvent?.primary_stage || 'RECONNAISSANCE'}`,
                    `CASE: ${activeCase.id}`,
                  ].map((step, idx) => (
                    <button
                      key={step}
                      onClick={() => setActiveProvenanceStep(idx)}
                      className={`text-left py-1 px-2 border transition-colors cursor-pointer ${
                        activeProvenanceStep === idx
                          ? 'border-[#F0C808] bg-[#111111] text-[#F0C808] font-bold'
                          : 'border-transparent text-[#c6c6c6] hover:border-[#262626] hover:bg-[#181818]'
                      }`}
                    >
                      <span className={activeProvenanceStep === idx ? 'text-[#F0C808] mr-2' : 'text-[#8e9192] mr-2'}>
                        ↓
                      </span>
                      {step}
                    </button>
                  ))}
                </div>
              </div>

              {/* Technical Raw Data Viewer */}
              <div className="flex flex-col bg-[#050505] border border-[#262626] p-3 font-metadata text-[10px]">
                <div className="flex justify-between items-center border-b border-[#262626] pb-2 mb-2">
                  <span className="text-white font-bold">RAW SOURCE VIEWER</span>
                  <span className="text-[#8e9192]">INGEST_GATEWAY_NODE_4</span>
                </div>
                <div className="text-[#8e9192] mb-1">
                  TELEMETRY OBSERVED: {liveEvent?.wall_clock_time || '2026-08-30 14:10:00 UTC'}
                </div>
                <pre className="text-white overflow-x-auto bg-[#000001] p-2 border border-[#262626] text-[9px] leading-tight">
{`{
  "target_node": "svc-api",
  "endpoint": "${activeCase.subject}",
  "port": 443,
  "flow_rate_pps": 1420.5,
  "stage": "${liveEvent?.primary_stage || 'RECONNAISSANCE'}"
}`}
                </pre>
                <div className="mt-2 border-t border-[#262626] pt-2">
                  <span className="text-white font-bold block mb-1 text-[9px]">NORMALIZED SIGNAL</span>
                  <div className="grid grid-cols-2 gap-1 text-[#8e9192] text-[9px]">
                    <span>entity: <span className="text-white">{activeCase.subject}</span></span>
                    <span>target: <span className="text-white">svc-api (Ingress Gateway)</span></span>
                  </div>
                </div>
              </div>

              {/* Consolidated Analyst Decision Hub */}
              <div className="flex flex-col border border-[#262626] p-3 bg-[#0A0A0A]">
                <h4 className="font-label-caps text-label-caps text-[#F0C808] uppercase border-b border-[#262626] pb-1 mb-2">
                  ANALYST REVIEW
                </h4>
                <div className="flex justify-between items-center py-1 font-metadata text-[10px]">
                  <span className="text-[#8e9192]">EVIDENCE ID</span>
                  <span className="text-white bg-[#111111] px-1 border border-[#262626]">
                    {activeCase.id === 'CASE-019' ? 'EV-00419' : 'EV-00421'}
                  </span>
                </div>
                <p className="font-metadata text-[10px] text-[#8e9192] mb-3">Links to Case State: PENDING_REVIEW.</p>
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      setNotification('EVIDENCE FLAGGED FOR RE-ANALYSIS');
                      setTimeout(() => setNotification(null), 3000);
                    }}
                    className="flex-1 border border-[#262626] text-[#8e9192] font-label-caps text-[10px] py-2 hover:bg-[#181818] hover:text-white transition-colors cursor-pointer"
                  >
                    FLAG
                  </button>
                  <button
                    onClick={handleVerifyDecision}
                    className="flex-1 border border-[#F0C808] bg-[#F0C808] text-black font-label-caps text-[10px] py-2 hover:bg-white transition-colors font-bold flex items-center justify-center gap-1 cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-[14px]">done</span> VERIFY
                  </button>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="grid grid-cols-2 gap-2 mt-auto pt-2 border-t border-[#262626]">
                <button
                  onClick={handleTraceBack}
                  className="border border-[#262626] text-[#8e9192] font-label-caps text-[10px] py-2 hover:bg-[#181818] hover:text-white transition-colors cursor-pointer"
                >
                  TRACE BACK
                </button>
                <button
                  onClick={handleTraceForward}
                  className="border border-[#F0C808] bg-[#F0C808] text-black font-label-caps text-[10px] py-2 hover:bg-white transition-colors font-bold cursor-pointer"
                >
                  TRACE FORWARD
                </button>
                <button
                  onClick={() => navigate('/command-center/evidence')}
                  className="border border-[#262626] text-white font-label-caps text-[10px] py-2 hover:bg-[#181818] transition-colors col-span-2 cursor-pointer"
                >
                  FOCUS PATH / VIEW EVIDENCE DRILL-DOWN
                </button>
              </div>

              {/* Keyboard Hints */}
              <div className="flex justify-between items-center border-t border-[#262626] pt-2 font-metadata text-[9px] text-[#8e9192]">
                <span><span className="border border-[#262626] px-1 mr-1">↵</span> OPEN</span>
                <span><span className="border border-[#262626] px-1 mr-1">ESC</span> BACK</span>
                <span><span className="border border-[#262626] px-1 mr-1">SPC</span> EXPAND</span>
              </div>
            </div>
          </aside>
        </section>

        {/* MODULE 4: Investigative Timeline */}
        <section className="bg-[#080808] h-[180px] shrink-0 p-8 relative flex flex-col justify-between border-t border-[#262626]">
          <div className="flex justify-between items-start z-10">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[#c6c6c6] text-[16px]">timeline</span>
              <span className="font-label-caps text-label-caps text-[#c6c6c6] uppercase tracking-widest">
                INVESTIGATIVE TIMELINE
              </span>
            </div>
            <div className="flex items-center gap-6">
              <div className="flex flex-col items-end">
                <span className="font-label-caps text-[9px] text-[#8e9192] uppercase">TEMPORAL SUMMARY</span>
                <span className="font-metadata text-[10px] text-white">OBS: 18 | CORR: 07 | ENT: 05</span>
              </div>
              <div className="flex gap-1 border border-[#262626] p-1 bg-[#0A0A0A]">
                {(['1H', '24H', '7D'] as const).map((r) => (
                  <button
                    key={r}
                    onClick={() => setTimelineRange(r)}
                    className={`px-2 py-1 text-[9px] font-label-caps transition-colors cursor-pointer ${
                      timelineRange === r ? 'bg-white text-black font-bold' : 'text-[#8e9192] hover:text-white'
                    }`}
                  >
                    {r}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="relative w-full h-12 mt-2 flex items-center">
            {/* Horizontal Line */}
            <div className="absolute left-0 right-0 h-[1px] bg-[#262626]"></div>

            {/* Timeline Markers */}
            <div className="absolute w-full flex justify-between px-12 z-10">
              {TIMELINE_MARKERS.map((marker) => {
                const isFocused = focusedMarkerId === marker.id;

                if (marker.id === 'tm-1') {
                  return (
                    <div
                      key={marker.id}
                      onClick={() => setFocusedMarkerId(marker.id)}
                      className="flex flex-col items-center gap-1 group cursor-pointer"
                    >
                      <div
                        className={`w-2 h-2 transition-colors ${
                          isFocused ? 'bg-[#F0C808]' : 'bg-[#8e9192] group-hover:bg-white'
                        }`}
                      ></div>
                      <span className="font-metadata text-[9px] text-[#8e9192] mt-6">{marker.date}</span>
                    </div>
                  );
                }

                if (marker.id === 'tm-3') {
                  return (
                    <div
                      key={marker.id}
                      onClick={() => setFocusedMarkerId(marker.id)}
                      className="flex flex-col items-center gap-1 group cursor-pointer"
                    >
                      <div className="w-4 h-4 bg-white border border-[#F0C808] flex items-center justify-center">
                        <div className="w-1 h-1 bg-black"></div>
                      </div>
                      <div className="absolute top-6 bg-[#111111] border border-[#F0C808] p-1 text-center w-36 shadow-[0_0_10px_rgba(240,200,8,0.2)] z-20">
                        <span className="font-metadata text-[9px] text-white font-bold">{marker.date}</span>
                        <br />
                        <span className="font-label-caps text-[10px] text-[#F0C808]">{marker.label}</span>
                      </div>
                    </div>
                  );
                }

                return (
                  <div
                    key={marker.id}
                    onClick={() => setFocusedMarkerId(marker.id)}
                    className="flex flex-col items-center gap-1 group cursor-pointer"
                  >
                    <div
                      className={`w-2 h-2 transition-colors ${
                        isFocused ? 'bg-[#F0C808]' : 'bg-[#8e9192] group-hover:bg-white'
                      }`}
                    ></div>
                    <span className="font-metadata text-[9px] text-[#8e9192] mt-6">{marker.date}</span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="flex items-center gap-4 mt-auto pt-2 border-t border-[#262626]">
            <span className="font-label-caps text-[9px] text-[#8e9192]">FILTERS:</span>
            <div className="flex gap-3">
              {(['OBSERVATION', 'CORRELATION', 'IDENTITY'] as const).map((sig) => (
                <button
                  key={sig}
                  onClick={() => setActiveSignalFilter(sig)}
                  className={`font-metadata text-[9px] transition-colors cursor-pointer ${
                    activeSignalFilter === sig
                      ? sig === 'CORRELATION'
                        ? 'text-[#F0C808] font-bold underline'
                        : 'text-white font-bold underline'
                      : 'text-[#8e9192] hover:text-white'
                  }`}
                >
                  {sig}
                </button>
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
