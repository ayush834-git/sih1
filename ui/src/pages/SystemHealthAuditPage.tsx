import React, { useState } from 'react';
import { useControlCenterStore } from '../store/useControlCenterStore';
import type { SystemStatusMode } from '../types/controlCenter';

export const SystemHealthAuditPage: React.FC = () => {
  const {
    systemMode,
    setSystemMode,
    auditLogs,
    selectedAudit,
    setSelectedAuditId,
    dataSources,
    models,
    setManualOverrideModalOpen,
  } = useControlCenterStore();

  const [activeTab, setActiveTab] = useState<'HEALTH' | 'AUDIT'>('HEALTH');
  const [selectedErrorFilter, setSelectedErrorFilter] = useState(false);

  const filteredLogs = selectedErrorFilter
    ? auditLogs.filter((l) => l.isError || l.result.includes('ERR') || l.result.includes('WARN') || l.result === 'FATAL')
    : auditLogs;

  return (
    <div className="p-8 min-h-full flex flex-col gap-6 bg-[#000001] text-white">
      {/* Top Header Strip with Mode Switcher & Tabs */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end border-b border-[#262626] pb-4 gap-4">
        <div>
          <div className="flex items-center gap-4 mb-2">
            <h2 className="font-headline-lg text-headline-lg uppercase tracking-tight">
              SYSTEM // {activeTab === 'HEALTH' ? 'SYSTEM HEALTH & OBSERVABILITY' : 'FORENSIC AUDIT TRAIL'}
            </h2>
            <div className="flex border border-[#262626] bg-[#080808] font-label-caps text-label-caps">
              <button
                onClick={() => setActiveTab('HEALTH')}
                className={`px-3 py-1 cursor-pointer transition-colors ${
                  activeTab === 'HEALTH' ? 'bg-white text-black font-bold' : 'text-[#c6c6c6] hover:text-white'
                }`}
              >
                HEALTH
              </button>
              <button
                onClick={() => setActiveTab('AUDIT')}
                className={`px-3 py-1 cursor-pointer transition-colors ${
                  activeTab === 'AUDIT' ? 'bg-white text-black font-bold' : 'text-[#c6c6c6] hover:text-white'
                }`}
              >
                AUDIT
              </button>
            </div>
          </div>
          <p className="font-metadata text-metadata text-[#c6c6c6]">
            Platform telemetry, pipeline health metrics, multi-state failure simulations, and tamper-evident logs.
          </p>
        </div>

        {/* State Switcher & Key Metrics */}
        <div className="flex flex-col md:flex-row items-start md:items-end gap-6">
          <div className="flex items-center border border-[#262626] bg-[#080808] font-label-caps text-label-caps">
            {(['NORMAL', 'DEGRADED', 'CRITICAL', 'RECOVERY'] as SystemStatusMode[]).map((mode) => (
              <button
                key={mode}
                onClick={() => setSystemMode(mode)}
                className={`px-3 py-1 border-r border-[#262626] last:border-r-0 cursor-pointer transition-colors ${
                  systemMode === mode
                    ? mode === 'CRITICAL' || mode === 'DEGRADED'
                      ? 'bg-[#111111] text-[#F0C808] font-bold border-[#F0C808]'
                      : 'bg-white text-black font-bold'
                    : 'text-[#8e9192] hover:text-white hover:bg-[#181818]'
                }`}
              >
                {mode}
              </button>
            ))}
          </div>

          <div className="flex space-x-6 font-metadata text-metadata text-[#8e9192] uppercase">
            <div className="flex flex-col">
              <span>UPTIME</span>
              <span className="text-white">99.97%</span>
            </div>
            <div className="flex flex-col">
              <span>ACTIVE SOURCES</span>
              <span className="text-white">18</span>
            </div>
            <div className="flex flex-col">
              <span>AUDIT EVENTS</span>
              <span className="text-white">{auditLogs.length}</span>
            </div>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────
          CRITICAL / EMERGENCY STATE VIEW
          ───────────────────────────────────────────── */}
      {systemMode === 'CRITICAL' && (
        <div className="grid grid-cols-12 gap-gutter bg-[#262626] p-[1px] animate-fade-in">
          {/* Left Column: Primary Emergency State (8 cols) */}
          <div className="col-span-12 lg:col-span-8 flex flex-col gap-gutter bg-[#262626]">
            {/* Main Status Block */}
            <div className="bg-[#080808] border-2 border-[#F0C808] p-8 flex flex-col justify-between min-h-[380px]">
              <div className="flex justify-between items-start mb-6">
                <div>
                  <div className="font-label-caps text-label-caps text-[#F0C808] mb-1">SYS_ERR_0X99F</div>
                  <h1 className="font-display-lg text-display-lg text-[#F0C808] tracking-tighter uppercase font-bold leading-none mb-2 text-[56px]">
                    CRITICAL<br />SYSTEM<br />CONDITION
                  </h1>
                  <div className="font-metadata text-metadata text-[#c6c6c6]">
                    T-MINUS 04:12:00 TO CORE DEGRADATION
                  </div>
                </div>
                <div className="font-metadata text-metadata text-right">
                  <div className="text-[#8e9192]">TIMESTAMP</div>
                  <div className="text-white">{new Date().toISOString()}</div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-8 border-t border-[#353535] pt-4">
                <div>
                  <div className="font-label-caps text-label-caps text-[#8e9192] mb-1">AUTONOMOUS AUTHORITY</div>
                  <div className="font-title-md text-title-md text-[#F0C808] uppercase">Suspended</div>
                </div>
                <div>
                  <div className="font-label-caps text-label-caps text-[#8e9192] mb-1">HUMAN CONTROL</div>
                  <div className="font-title-md text-title-md text-white uppercase animate-pulse border border-white px-2 py-1 inline-block">
                    Required
                  </div>
                </div>
              </div>

              <div className="mt-6">
                <button
                  onClick={() => setManualOverrideModalOpen(true)}
                  className="w-full bg-[#F0C808] text-[#000001] font-title-md text-title-md uppercase py-4 cursor-pointer hover:bg-white transition-colors flex items-center justify-center font-bold"
                >
                  INITIATE MANUAL OVERRIDE
                  <span className="material-symbols-outlined ml-2 text-[24px]">warning</span>
                </button>
              </div>
            </div>

            {/* Pipeline Status */}
            <div className="bg-[#080808] p-8 border border-[#262626]">
              <div className="flex justify-between items-center mb-4">
                <div className="font-label-caps text-label-caps text-white uppercase">Affected Pipelines</div>
                <div className="font-metadata text-metadata text-[#F0C808] font-bold">3 FAILED / 2 DEGRADED</div>
              </div>
              <div className="space-y-2 bg-[#080808]">
                <div className="bg-[#111111] flex justify-between items-center p-3 border-l-2 border-[#F0C808]">
                  <div className="flex items-center space-x-3">
                    <span className="material-symbols-outlined text-[#F0C808]">memory</span>
                    <div>
                      <div className="font-label-caps text-label-caps text-white">NODE_ALPHA_01</div>
                      <div className="font-metadata text-metadata text-[#8e9192]">DATA INGESTION MODULE</div>
                    </div>
                  </div>
                  <div className="font-metadata text-metadata text-[#F0C808] uppercase font-bold">Failed</div>
                </div>
                <div className="bg-[#111111] flex justify-between items-center p-3 border-l-2 border-[#F0C808]">
                  <div className="flex items-center space-x-3">
                    <span className="material-symbols-outlined text-[#F0C808]">storage</span>
                    <div>
                      <div className="font-label-caps text-label-caps text-white">DATABASE_CLUSTER_C</div>
                      <div className="font-metadata text-metadata text-[#8e9192]">QUERY ROUTING</div>
                    </div>
                  </div>
                  <div className="font-metadata text-metadata text-[#F0C808] uppercase font-bold">Failed</div>
                </div>
                <div className="bg-[#111111] flex justify-between items-center p-3 border-l-2 border-[#F0C808]">
                  <div className="flex items-center space-x-3">
                    <span className="material-symbols-outlined text-[#F0C808]">router</span>
                    <div>
                      <div className="font-label-caps text-label-caps text-white">NETWORK_GATEWAY_EXT</div>
                      <div className="font-metadata text-metadata text-[#8e9192]">EXTERNAL API FACING</div>
                    </div>
                  </div>
                  <div className="font-metadata text-metadata text-[#F0C808] uppercase font-bold">Failed</div>
                </div>
                <div className="bg-[#111111] flex justify-between items-center p-3 border-l-2 border-[#444748]">
                  <div className="flex items-center space-x-3">
                    <span className="material-symbols-outlined text-[#8e9192]">dns</span>
                    <div>
                      <div className="font-label-caps text-label-caps text-white">CACHE_LAYER_L2</div>
                      <div className="font-metadata text-metadata text-[#8e9192]">REDIS CLUSTER</div>
                    </div>
                  </div>
                  <div className="font-metadata text-metadata text-white uppercase">Degraded</div>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Audit Trail & Diagnostics (4 cols) */}
          <div className="col-span-12 lg:col-span-4 flex flex-col gap-gutter bg-[#262626]">
            <div className="bg-[#080808] p-8 border border-[#262626] flex-grow flex flex-col">
              <div className="flex justify-between items-center mb-4 pb-2 border-b border-[#262626]">
                <div className="font-label-caps text-label-caps text-white uppercase">Emergency Audit Stream</div>
                <span className="material-symbols-outlined text-[#8e9192] text-[16px]">list_alt</span>
              </div>
              <div className="overflow-y-auto flex-grow space-y-3 font-metadata text-metadata">
                <div className="border-b border-[#181818] pb-2">
                  <span className="text-[#8e9192] mr-2">[09:42:11]</span>
                  <span className="text-[#F0C808] font-bold uppercase">
                    FATAL: Kernel panic - not syncing: VFS: Unable to mount root fs on shard-03
                  </span>
                </div>
                <div className="border-b border-[#181818] pb-2">
                  <span className="text-[#8e9192] mr-2">[09:42:08]</span>
                  <span className="text-[#F0C808] font-bold uppercase">
                    ERROR: Primary filesystem integrity check failed.
                  </span>
                </div>
                <div className="border-b border-[#181818] pb-2">
                  <span className="text-[#8e9192] mr-2">[09:41:55]</span>
                  <span className="text-white">WARN: Unusual latency detected on I/O bus 2.</span>
                </div>
                <div className="border-b border-[#181818] pb-2">
                  <span className="text-[#8e9192] mr-2">[09:41:40]</span>
                  <span className="text-[#F0C808] font-bold uppercase">
                    ERROR: Connection lost to node NODE_ALPHA_01. Timeout exceeded.
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────
          DEGRADED STATE VIEW
          ───────────────────────────────────────────── */}
      {systemMode === 'DEGRADED' && (
        <div className="grid grid-cols-12 gap-gutter bg-[#262626] p-[1px] animate-fade-in">
          {/* Alert Banner */}
          <div className="col-span-12 bento-module p-4 bg-[#111111] flex items-center justify-between border-l-4 border-l-[#F0C808]">
            <div className="flex items-center gap-4">
              <span className="material-symbols-outlined text-[#F0C808] text-2xl">warning</span>
              <div>
                <div className="font-label-caps text-label-caps text-[#F0C808]">
                  SYSTEM ALERT: DEGRADED PERFORMANCE DETECTED
                </div>
                <div className="font-metadata text-metadata text-[#c6c6c6] mt-1">
                  Data pipeline latency exceeding operational thresholds. Fallback protocols initiated.
                </div>
              </div>
            </div>
            <div className="font-metadata text-metadata text-[#8e9192]">TS: {new Date().toISOString()}</div>
          </div>

          {/* Status Indicator (4 cols) */}
          <div className="col-span-12 md:col-span-4 bento-module bg-[#080808] flex flex-col justify-between">
            <div className="flex justify-between items-start mb-6">
              <div className="font-label-caps text-label-caps text-[#8e9192]">OVERALL STATUS</div>
              <div className="font-metadata text-metadata text-[#8e9192]">SYS_ID: 0x8F2A</div>
            </div>
            <div>
              <div className="font-display-lg text-display-lg text-[#F0C808] leading-none mb-2 font-mono text-[48px]">
                DEGRADED
              </div>
              <div className="font-metadata text-metadata text-[#8e9192] border-t border-[#262626] pt-2 mt-4">
                CORE_INFRASTRUCTURE: <span className="text-white">ONLINE</span>
                <br />
                DATA_INGESTION: <span className="text-[#F0C808]">IMPAIRED</span>
              </div>
            </div>
          </div>

          {/* Metrics (4 cols) */}
          <div className="col-span-12 md:col-span-4 bento-module bg-[#111111] border border-[#353535] flex flex-col justify-between">
            <div className="flex justify-between items-start mb-6">
              <div className="font-label-caps text-label-caps text-white">OBSERVABILITY INDEX</div>
              <div className="font-metadata text-metadata text-[#8e9192]">LIVESTREAM</div>
            </div>
            <div>
              <div className="flex items-end gap-2 mb-2">
                <span className="font-headline-lg text-headline-lg text-[#F0C808]">64%</span>
                <span className="font-metadata text-metadata text-[#8e9192] mb-1">▼ REDUCED FROM 98%</span>
              </div>
              <div className="w-full h-1 bg-[#262626] mt-4">
                <div className="h-full dashed-progress w-[64%]"></div>
              </div>
              <div className="flex justify-between mt-2 font-metadata text-metadata text-[#8e9192]">
                <span>0%</span>
                <span>TARGET: 99.9%</span>
              </div>
            </div>
          </div>

          {/* Interventions (4 cols) */}
          <div className="col-span-12 md:col-span-4 bento-module bg-[#080808] flex flex-col">
            <div className="flex justify-between items-start mb-6">
              <div className="font-label-caps text-label-caps text-white">AFFECTED INVESTIGATIONS</div>
              <div className="bg-[#181818] px-2 py-1 font-label-caps text-label-caps text-[#F0C808]">ACT REQ</div>
            </div>
            <div className="flex items-center gap-4 mb-6">
              <span className="font-display-lg text-display-lg text-white leading-none text-[48px]">4</span>
              <span className="font-metadata text-metadata text-[#8e9192] uppercase w-28 leading-tight">
                Cases Requiring Manual Intervention
              </span>
            </div>
            <div className="flex-1 flex flex-col gap-2">
              <div className="flex justify-between border-b border-[#262626] pb-2 font-metadata text-metadata">
                <span className="text-white">INV-8821</span>
                <span className="text-[#F0C808]">SYNC FAILED</span>
              </div>
              <div className="flex justify-between border-b border-[#262626] pb-2 font-metadata text-metadata">
                <span className="text-white">INV-8819</span>
                <span className="text-[#F0C808]">DATA STALE</span>
              </div>
            </div>
          </div>

          {/* Dense Forensic Audit Trail (8 cols) */}
          <div className="col-span-12 md:col-span-8 bento-module bg-[#080808] flex flex-col">
            <div className="flex justify-between items-start mb-6 border-b border-[#262626] pb-4">
              <div className="font-label-caps text-label-caps text-white">FORENSIC AUDIT TRAIL</div>
              <div className="flex gap-4 font-metadata text-metadata text-[#8e9192]">
                <span>MODE: DENSE</span>
                <span>FILTERS: ERRORS ONLY</span>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto">
              <table className="w-full text-left border-collapse font-metadata text-metadata">
                <thead>
                  <tr className="text-[#8e9192] border-b border-[#262626]">
                    <th className="pb-2 font-normal">TIMESTAMP</th>
                    <th className="pb-2 font-normal">SERVICE</th>
                    <th className="pb-2 font-normal">EVENT_CODE</th>
                    <th className="pb-2 font-normal">DETAIL</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-[#181818] hover:bg-[#111111]">
                    <td className="py-2 text-[#8e9192]">14:32:00.045</td>
                    <td className="py-2 text-white">DATA_NODE_03</td>
                    <td className="py-2 text-[#F0C808]">ERR_TIMEOUT</td>
                    <td className="py-2 text-[#c6c6c6] truncate max-w-[200px]">Handshake failed after 3000ms. Retrying...</td>
                  </tr>
                  <tr className="border-b border-[#181818] hover:bg-[#111111]">
                    <td className="py-2 text-[#8e9192]">14:31:58.912</td>
                    <td className="py-2 text-white">AUTH_GATEWAY</td>
                    <td className="py-2 text-white">WARN_LATENCY</td>
                    <td className="py-2 text-[#c6c6c6] truncate max-w-[200px]">Token validation took 450ms (Expected &lt; 50ms)</td>
                  </tr>
                  <tr className="border-b border-[#181818] hover:bg-[#111111]">
                    <td className="py-2 text-[#8e9192]">14:31:45.221</td>
                    <td className="py-2 text-white">MODEL_INFERENCE</td>
                    <td className="py-2 text-[#F0C808]">ERR_DEGRADED</td>
                    <td className="py-2 text-[#c6c6c6] truncate max-w-[200px]">Falling back to secondary model parameters.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* System Authority & Data Sources (4 cols) */}
          <div className="col-span-12 md:col-span-4 bento-module bg-[#080808] flex flex-col justify-between">
            <div>
              <div className="font-label-caps text-label-caps text-[#8e9192] mb-4">SYSTEM AUTHORITY</div>
              <div className="mb-4">
                <div className="font-metadata text-metadata text-[#8e9192] mb-1">MODEL CONFIDENCE</div>
                <div className="font-title-md text-title-md text-[#F0C808]">DECLINING</div>
              </div>
              <div className="mb-4">
                <div className="font-metadata text-metadata text-[#8e9192] mb-1">AUTONOMOUS AUTHORITY</div>
                <div className="font-title-md text-title-md text-white">LIMITED</div>
              </div>
              <div className="border-t border-[#262626] pt-4">
                <div className="font-metadata text-metadata text-[#8e9192] mb-1">HUMAN REVIEW REQUIREMENT</div>
                <div className="font-title-md text-title-md text-white">INCREASED</div>
              </div>
            </div>
            <button
              onClick={() => setManualOverrideModalOpen(true)}
              className="mt-6 w-full py-2 bg-[#F0C808] text-black font-label-caps text-label-caps font-bold hover:bg-white transition-colors cursor-pointer"
            >
              TRIGGER OVERRIDE
            </button>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────
          NORMAL / RECOVERY STANDARD VIEW
          ───────────────────────────────────────────── */}
      {(systemMode === 'NORMAL' || systemMode === 'RECOVERY') && (
        <div className="bento-grid grid-cols-12 gap-gutter bg-[#262626] p-[1px] animate-fade-in">
          {/* Engine State & Impact Propagation Motion Matrix (12 cols) */}
          <div className="col-span-12 grid grid-cols-12 gap-gutter bg-[#262626] border border-[#262626]">
            {/* Left Col: Engine Vitality */}
            <div className="col-span-12 lg:col-span-3 bg-[#080808] p-6 flex flex-col justify-between">
              <div>
                <h3 className="font-label-caps text-label-caps text-white uppercase tracking-widest mb-4 flex justify-between">
                  <span>ENGINE VITALITY</span>
                  <span className="text-[#8e9192]">SYS-01</span>
                </h3>
                <div className="mb-6">
                  <div className="flex justify-between font-metadata text-metadata mb-1">
                    <span className="text-[#8e9192]">CONFIDENCE_SCORE</span>
                    <span className="text-[#F0C808] font-bold">91%</span>
                  </div>
                  <div className="w-full h-1 bg-[#181818]">
                    <div className="h-full bg-[#F0C808] w-[91%]"></div>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="font-label-caps text-[11px] text-[#8e9192] uppercase">ACTIVE PROTOCOLS</div>
                <div className="space-y-2 font-metadata text-metadata border-t border-[#262626] pt-2">
                  <div className="flex justify-between items-center">
                    <span className="text-white">THREAT_ATTRIBUTION</span>
                    <span className="text-[#F0C808] font-bold animate-pulse">ACTIVE</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-white">PATTERN_RECOGNITION</span>
                    <span className="text-[#F0C808] font-bold animate-pulse">ACTIVE</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[#8e9192]">ARCHIVE_SYNC</span>
                    <span className="text-[#8e9192]">IDLE</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Center Col: Data Stream Scanner */}
            <div className="col-span-12 lg:col-span-5 bg-[#080808] p-6 relative overflow-hidden flex flex-col justify-between">
              <div className="flex justify-between items-center mb-4">
                <h3 className="font-label-caps text-label-caps text-white uppercase tracking-widest">
                  DATA STREAM
                </h3>
                <span className="font-metadata text-metadata text-[#F0C808] border border-[#F0C808] px-2 py-0.5">
                  LIVE FEED
                </span>
              </div>

              <div className="flex-1 overflow-y-auto font-metadata text-metadata space-y-2 pr-2">
                <div className="text-[#8e9192] flex gap-3">
                  <span>[14:02:01]</span>
                  <span>SIG_INT: PACKET_LOSS DETECTED AT NODE_7</span>
                </div>
                <div className="text-[#8e9192] flex gap-3">
                  <span>[14:02:05]</span>
                  <span>AUTO_RESOLVE: REROUTING TRAFFIC VIA NODE_9</span>
                </div>
                <div className="text-white flex gap-3">
                  <span>[14:03:10]</span>
                  <span className="text-[#F0C808] font-bold">ALERT: UNKNOWN_SIGNATURE_DETECTED</span>
                </div>
                <div className="text-white flex gap-3">
                  <span>[14:03:11]</span>
                  <span>INITIATING DEEP SCAN...</span>
                </div>
                <div className="text-white flex gap-3 mt-2">
                  <span>[14:03:12]</span>
                  <span className="typing-effect text-[#F0C808] font-bold">
                    MATCH_FOUND: THREAT_ACTOR_04 (CONFIDENCE: 92%)
                  </span>
                </div>
              </div>

              {/* Scanner Line Overlay */}
              <div className="absolute inset-x-0 h-[1px] bg-[#F0C808]/50 shadow-[0_0_10px_#F0C808] animate-[scan_4s_ease-in-out_infinite]"></div>
            </div>

            {/* Right Col: Impact Propagation SVG Graph */}
            <div className="col-span-12 lg:col-span-4 bg-[#080808] p-6 flex flex-col justify-between">
              <div className="flex justify-between items-center mb-3">
                <h3 className="font-label-caps text-label-caps text-white uppercase tracking-widest flex items-center gap-2">
                  <span>IMPACT PROPAGATION</span>
                  <span className="material-symbols-outlined text-[#F0C808] text-[16px]">notifications_active</span>
                </h3>
              </div>

              {/* SVG Topology */}
              <div className="h-32 border border-[#262626] bg-[#050505] relative flex items-center justify-center p-2 mb-3">
                <svg className="w-full h-full" viewBox="0 0 300 120">
                  <line x1="40" y1="60" x2="130" y2="25" stroke="#353535" strokeWidth="1" />
                  <line x1="40" y1="60" x2="130" y2="95" stroke="#353535" strokeWidth="1" />
                  <line x1="130" y1="25" x2="230" y2="60" stroke="#F0C808" strokeWidth="2" />
                  <line x1="130" y1="95" x2="230" y2="60" stroke="#F0C808" strokeWidth="2" className="dash-flow-anim" />

                  <g className="cursor-pointer group">
                    <circle cx="40" cy="60" r="4" fill="#353535" className="breathe-node" />
                    <text x="30" y="48" fill="#8e9192" fontSize="9" fontFamily="JetBrains Mono">NODE_01</text>
                  </g>
                  <g className="cursor-pointer group">
                    <circle cx="130" cy="25" r="4" fill="#353535" className="breathe-node" />
                    <text x="120" y="15" fill="#8e9192" fontSize="9" fontFamily="JetBrains Mono">NODE_14</text>
                  </g>
                  <g className="cursor-pointer group">
                    <circle cx="130" cy="95" r="4" fill="#353535" className="breathe-node" />
                    <text x="120" y="112" fill="#8e9192" fontSize="9" fontFamily="JetBrains Mono">NODE_22</text>
                  </g>
                  <g className="cursor-pointer group">
                    <circle cx="230" cy="60" r="6" fill="#F0C808" className="breathe-active-node" />
                    <text x="215" y="48" fill="#F0C808" fontSize="9" fontFamily="JetBrains Mono" fontWeight="bold">NODE_250</text>
                  </g>
                </svg>
                <div className="absolute bottom-1 right-2 font-metadata text-[9px] text-[#F0C808] animate-pulse">
                  NODE_250 ISOLATED
                </div>
              </div>

              {/* Review Queue Preview */}
              <div className="border border-[#F0C808] bg-[#111111] p-3 flex flex-col gap-1">
                <div className="flex justify-between items-center">
                  <span className="font-label-caps text-label-caps text-white font-bold">ID_84729A</span>
                  <span className="font-metadata text-metadata text-[#F0C808] uppercase">NEW ALERT</span>
                </div>
                <div className="flex justify-between font-metadata text-[10px]">
                  <span className="text-[#8e9192]">ACTION</span>
                  <span className="text-[#F0C808]">AWAITING_REVIEW</span>
                </div>
              </div>
            </div>
          </div>

          {/* Audit Trail Chronological Log (8 cols) */}
          <div className="bento-module col-span-12 md:col-span-8 flex flex-col h-[450px] bg-[#080808]">
            <div className="flex justify-between items-start mb-4 border-b border-[#262626] pb-2">
              <h3 className="font-label-caps text-label-caps uppercase text-white">
                Audit Trail (Chronological Log)
              </h3>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setSelectedErrorFilter(!selectedErrorFilter)}
                  className={`px-2 py-0.5 border text-[10px] font-metadata cursor-pointer ${
                    selectedErrorFilter ? 'border-[#F0C808] text-[#F0C808]' : 'border-[#262626] text-[#8e9192]'
                  }`}
                >
                  {selectedErrorFilter ? 'ERRORS ONLY' : 'ALL EVENTS'}
                </button>
                <span className="font-metadata text-metadata text-[#8e9192]">LATEST: T-0.001s</span>
              </div>
            </div>
            <div className="flex-1 overflow-hidden flex flex-col">
              <div className="grid grid-cols-12 gap-2 font-metadata text-metadata text-[#8e9192] pb-2 border-b border-[#262626] uppercase">
                <div className="col-span-3">TIMESTAMP</div>
                <div className="col-span-2">ACTOR</div>
                <div className="col-span-3">ACTION</div>
                <div className="col-span-2">OBJECT</div>
                <div className="col-span-2 text-right">RESULT</div>
              </div>
              <div className="flex-1 overflow-y-auto font-metadata text-metadata">
                {filteredLogs.map((log) => {
                  const isSelected = selectedAudit.id === log.id;
                  return (
                    <div
                      key={log.id}
                      onClick={() => setSelectedAuditId(log.id)}
                      className={`grid grid-cols-12 gap-2 py-2 border-b border-[#262626] px-2 cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-[#111111] border border-[#F0C808] text-white'
                          : 'text-[#c6c6c6] hover:bg-[#111111]'
                      }`}
                    >
                      <div className="col-span-3 truncate">{log.timestamp}</div>
                      <div className="col-span-2 text-white font-bold">{log.actor}</div>
                      <div className="col-span-3 truncate">{log.action}</div>
                      <div className="col-span-2 truncate text-[#8e9192]">{log.object}</div>
                      <div
                        className={`col-span-2 text-right ${
                          log.result === 'SUCCESS'
                            ? 'text-[#F0C808]'
                            : log.result.includes('ERR') || log.result === 'FATAL'
                            ? 'text-[#ffb4ab]'
                            : 'text-white'
                        }`}
                      >
                        {log.result}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Observability (4 cols) */}
          <div className="bento-module col-span-12 md:col-span-4 flex flex-col h-[450px] bg-[#080808]">
            <div className="flex justify-between items-start mb-4">
              <h3 className="font-label-caps text-label-caps uppercase text-white">Observability Coverage</h3>
              <span className="font-metadata text-metadata text-[#8e9192]">SIG_DENS</span>
            </div>
            <div className="flex-1 flex flex-col justify-end border-b border-l border-[#262626] relative overflow-hidden">
              <div className="absolute bottom-0 left-0 w-full h-[70%] flex items-end opacity-60">
                <div className="w-1/6 h-[30%] bg-white border-t border-white mr-[1px]"></div>
                <div className="w-1/6 h-[45%] bg-white border-t border-white mr-[1px]"></div>
                <div className="w-1/6 h-[20%] bg-white border-t border-white mr-[1px]"></div>
                <div className="w-1/6 h-[70%] bg-white border-t border-white mr-[1px]"></div>
                <div className="w-1/6 h-[60%] bg-white border-t border-white mr-[1px]"></div>
                <div className="w-1/6 h-[85%] bg-[#F0C808] border-t border-[#F0C808]"></div>
              </div>
            </div>
            <div className="flex justify-between mt-2 font-metadata text-metadata text-[#8e9192]">
              <span>T-60m</span>
              <span>NOW</span>
            </div>
          </div>

          {/* Data Sources Throughput (6 cols) */}
          <div className="bento-module col-span-12 md:col-span-6 flex flex-col h-[280px] bg-[#080808]">
            <div className="flex justify-between items-start mb-4 border-b border-[#262626] pb-2">
              <h3 className="font-label-caps text-label-caps uppercase text-white">Data Sources Throughput</h3>
              <span className="font-metadata text-metadata text-[#8e9192]">ACTIVE: {dataSources.length}</span>
            </div>
            <div className="flex-1 overflow-y-auto">
              <table className="w-full font-metadata text-metadata text-left">
                <thead className="text-[#8e9192] border-b border-[#262626]">
                  <tr>
                    <th className="pb-2 font-normal">SOURCE</th>
                    <th className="pb-2 font-normal">RATE</th>
                    <th className="pb-2 font-normal text-right">STATUS</th>
                  </tr>
                </thead>
                <tbody className="text-white">
                  {dataSources.map((ds) => (
                    <tr key={ds.id} className="border-b border-[#262626] hover:bg-[#111111] transition-colors">
                      <td className="py-2">{ds.name}</td>
                      <td className="py-2 text-[#c6c6c6]">{ds.rate}</td>
                      <td className="py-2 text-right text-white font-bold">{ds.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Model Status & Confidence (6 cols) */}
          <div className="bento-module col-span-12 md:col-span-6 flex flex-col h-[280px] bg-[#080808]">
            <div className="flex justify-between items-start mb-4 border-b border-[#262626] pb-2">
              <h3 className="font-label-caps text-label-caps uppercase text-white">Model Status & Confidence</h3>
              <span className="font-metadata text-metadata text-[#8e9192]">VER: MULTI</span>
            </div>
            <div className="flex-1 overflow-y-auto space-y-3 font-metadata text-metadata">
              {models.map((m) => (
                <div
                  key={m.name}
                  className={`flex justify-between items-center border-b pb-2 ${
                    m.isWarning ? 'border-[#F0C808] bg-[#111111] px-2' : 'border-[#262626]'
                  }`}
                >
                  <div>
                    <div className={m.isWarning ? 'text-[#F0C808] font-bold' : 'text-white'}>{m.name}</div>
                    <div className="text-[#8e9192] text-[10px]">
                      {m.version} | Drift: <span className={m.isWarning ? 'text-[#F0C808]' : ''}>{m.drift}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={m.isWarning ? 'text-[#F0C808] font-bold' : 'text-white'}>{m.confidence}%</div>
                    <div className="text-[#8e9192] text-[10px]">CONFIDENCE</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
