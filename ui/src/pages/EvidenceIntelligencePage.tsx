import React, { useState } from 'react';
import { useControlCenterStore } from '../store/useControlCenterStore';
import { useRuntimeStore } from '../store/useRuntimeStore';
import { useNavigate } from 'react-router-dom';

export const EvidenceIntelligencePage: React.FC = () => {
  const {
    selectedEvidence,
    updateEvidenceReview,
    setFocusedEntityId,
    setActiveCaseId,
  } = useControlCenterStore();
  const { snapshot } = useRuntimeStore();
  const liveEvent = snapshot.event;
  const secExpl = liveEvent?.security_explanation;

  const [analystNotes, setAnalystNotes] = useState(
    'Anomalous routing pattern detected involving autonomous system AS-65001. Heuristic review suggests a masked exfiltration channel established via compromised edge nodes.'
  );
  const [notification, setNotification] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleAcceptEvidence = () => {
    updateEvidenceReview(selectedEvidence.id, 'VERIFIED', 'SUPPORTING', analystNotes);
    setNotification(`EVIDENCE ${selectedEvidence.id} ACCEPTED AND VERIFIED`);
    setTimeout(() => setNotification(null), 3000);
  };

  const handleMarkConflicting = () => {
    updateEvidenceReview(selectedEvidence.id, 'REVIEWED', 'CONFLICTING', analystNotes);
    setNotification(`EVIDENCE ${selectedEvidence.id} MARKED AS CONFLICTING`);
    setTimeout(() => setNotification(null), 3000);
  };

  const handleEscalate = () => {
    setNotification(`EVIDENCE ${selectedEvidence.id} ESCALATED TO LEAD THREAT INTEL`);
    setTimeout(() => setNotification(null), 3000);
  };

  const handleRequestMoreEv = () => {
    setNotification('EXPANDED TELEMETRY REQUEST DISPATCHED TO INGESTION BUFFER');
    setTimeout(() => setNotification(null), 3000);
  };

  const displayId = liveEvent ? `EV-T${String(liveEvent.step_index).padStart(2, '0')}` : selectedEvidence.id;
  const displayType = liveEvent ? liveEvent.primary_stage : selectedEvidence.type;
  const displayCaseId = liveEvent ? 'CASE-019' : selectedEvidence.caseId;
  const displaySource = liveEvent ? 'CIC-IDS2018 / AR(5) INGEST' : selectedEvidence.source;
  const displayCollectedAt = liveEvent ? (liveEvent.wall_clock_time || liveEvent.logical_time_str) : selectedEvidence.collectedAt;
  const displaySummary = liveEvent ? (liveEvent.explanation || 'Evaluated window telemetry state.') : selectedEvidence.description;

  const flowSummary = liveEvent?.current_state_summary;
  const statPackets = flowSummary ? Math.round(flowSummary.flow_count * 10) : (selectedEvidence.packets || 89);
  const statVolume = flowSummary ? `${(flowSummary.byte_rate / 1024).toFixed(1)}K` : (selectedEvidence.volume || '1.2G');
  const statHops = flowSummary ? Math.round(flowSummary.dst_port_diversity) : (selectedEvidence.hops || 4);
  const statDuration = flowSummary ? `${(flowSummary.mean_flow_duration ?? 1.2).toFixed(1)}s` : (selectedEvidence.duration || '12s');

  return (
    <div className="flex flex-col h-full bg-[#000001] text-white overflow-hidden">
      {/* Toast Notification */}
      {notification && (
        <div className="absolute top-4 right-8 z-50 bg-[#111111] border border-[#F0C808] text-[#F0C808] px-4 py-2 font-label-caps text-label-caps flex items-center gap-2 shadow-2xl animate-fade-in">
          <span className="material-symbols-outlined text-[18px]">verified</span>
          <span>{notification}</span>
        </div>
      )}

      {/* Header Section */}
      <header className="px-8 py-4 border-b border-[#262626] flex flex-col md:flex-row justify-between items-start md:items-end bg-[#080808] gap-4 shrink-0">
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-3">
            <span className="bg-[#111111] px-2 py-0.5 font-metadata text-metadata text-[#c6c6c6] border border-[#262626] uppercase">
              EVIDENCE ITEM
            </span>
            <span className="font-metadata text-metadata text-[#8e9192]">ID: {displayId}</span>
          </div>
          <h1 className="font-headline-lg text-headline-lg text-white tracking-tight uppercase flex items-center gap-3 text-[26px]">
            {displayId} <span className="text-[#353535]">|</span> {displayType}{' '}
            <span className="text-[#353535]">|</span> {displayCaseId}
          </h1>
        </div>

        <div className="flex items-center gap-6 font-label-caps text-label-caps text-[#8e9192]">
          <button
            onClick={() => {
              setFocusedEntityId('ent-1');
              navigate('/command-center/intelligence');
            }}
            className="hover:text-white flex items-center gap-1 transition-colors cursor-pointer"
          >
            <span className="material-symbols-outlined text-sm">visibility</span> VIEW ENTITY
          </button>
          <button
            onClick={() => {
              setActiveCaseId(displayCaseId);
              navigate('/command-center/investigations');
            }}
            className="hover:text-white flex items-center gap-1 transition-colors cursor-pointer"
          >
            <span className="material-symbols-outlined text-sm">account_tree</span> VIEW RELATIONSHIP
          </button>
          <button
            onClick={() => navigate('/command-center/system')}
            className="hover:text-white flex items-center gap-1 transition-colors cursor-pointer"
          >
            <span className="material-symbols-outlined text-sm">history</span> VIEW AUDIT
          </button>
        </div>
      </header>

      {/* Bento Grid Layout */}
      <div className="flex-1 p-8 overflow-y-auto bg-[#000001]">
        <div className="grid grid-cols-12 gap-gutter bg-[#262626] border border-[#262626] min-h-[780px]">
          {/* Left Column (Span 8) */}
          <div className="col-span-12 xl:col-span-8 flex flex-col gap-gutter bg-[#262626]">
            {/* Primary Panel: Evidence Detail */}
            <section className="bg-[#080808] p-8 flex-1 flex flex-col relative group">
              <div className="absolute top-0 left-0 bg-[#181818] text-white font-label-caps text-label-caps px-3 py-1 flex items-center gap-2 border-b border-r border-[#262626]">
                <span className="w-1.5 h-1.5 bg-white"></span>
                EVIDENCE DETAIL
              </div>
              <div className="absolute top-4 right-4 font-metadata text-metadata text-[#8e9192]">
                {liveEvent
                  ? `LOGICAL: ${liveEvent.logical_time_str} | OBSERVED: ${liveEvent.wall_clock_time}`
                  : 'OBSERVED: 2026-08-30 14:10:00 UTC'}
              </div>

              <div className="mt-8 flex flex-col gap-6">
                <div className="grid grid-cols-2 gap-4 border-b border-[#262626] pb-4">
                  <div className="flex flex-col gap-1">
                    <span className="font-metadata text-metadata text-[#8e9192] uppercase">Source</span>
                    <span className="font-label-caps text-label-caps text-white">{displaySource}</span>
                  </div>
                  <div className="flex flex-col gap-1">
                    <span className="font-metadata text-metadata text-[#8e9192] uppercase">
                      {liveEvent ? 'Observed Time (UTC)' : 'Collected Timestamp'}
                    </span>
                    <span className="font-label-caps text-label-caps text-white">{displayCollectedAt}</span>
                  </div>
                </div>

                <div className="flex flex-col gap-2">
                  <span className="font-metadata text-metadata text-[#8e9192] uppercase">Observation Summary</span>
                  <p className="font-body-rg text-[14px] text-white leading-relaxed max-w-3xl">
                    {displaySummary}
                  </p>
                </div>

                {/* 4-Stat Metric Grid */}
                <div className="mt-auto grid grid-cols-4 gap-gutter bg-[#262626] border border-[#262626]">
                  <div className="bg-[#080808] p-4 flex flex-col items-center justify-center">
                    <span className="font-headline-lg text-headline-lg-mobile text-white font-bold">
                      {statPackets}
                    </span>
                    <span className="font-metadata text-metadata text-[#8e9192]">FLOWS</span>
                  </div>
                  <div className="bg-[#080808] p-4 flex flex-col items-center justify-center">
                    <span className="font-headline-lg text-headline-lg-mobile text-white font-bold">
                      {statVolume}
                    </span>
                    <span className="font-metadata text-metadata text-[#8e9192]">BYTE RATE</span>
                  </div>
                  <div className="bg-[#080808] p-4 flex flex-col items-center justify-center">
                    <span className="font-headline-lg text-headline-lg-mobile text-white font-bold">
                      {statHops}
                    </span>
                    <span className="font-metadata text-metadata text-[#8e9192]">PORT DIV</span>
                  </div>
                  <div className="bg-[#080808] p-4 flex flex-col items-center justify-center">
                    <span className="font-headline-lg text-headline-lg-mobile text-white font-bold">
                      {statDuration}
                    </span>
                    <span className="font-metadata text-metadata text-[#8e9192]">DURATION</span>
                  </div>
                </div>
              </div>
            </section>

            {/* Conflict Analysis Panel */}
            <section className="bg-[#080808] p-8 flex-1 flex flex-col relative group border border-transparent hover:border-[#353535] transition-colors">
              <div className="absolute top-0 left-0 bg-[#181818] text-white font-label-caps text-label-caps px-3 py-1 flex items-center gap-2 border-b border-r border-[#262626]">
                <span className="material-symbols-outlined text-sm">compare_arrows</span>
                CONFLICT ANALYSIS
              </div>

              <div className="mt-8 h-full flex flex-col">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-gutter bg-[#262626] h-full flex-1">
                  {/* Supporting Signals */}
                  <div className="bg-[#080808] p-6 flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-[#262626] pb-2">
                      <span className="font-label-caps text-label-caps text-white">SUPPORTING SIGNALS</span>
                      <span className="font-metadata text-metadata text-[#8e9192] px-2 py-0.5 bg-[#111111]">
                        MATCH: {secExpl?.supporting_evidence?.length || selectedEvidence.supportingSignals?.length || 1}
                      </span>
                    </div>
                    <ul className="flex flex-col gap-3 font-metadata text-metadata text-[#c6c6c6]">
                      {secExpl?.supporting_evidence && secExpl.supporting_evidence.length > 0 ? (
                        secExpl.supporting_evidence.map((sig, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="material-symbols-outlined text-white text-sm mt-0.5">check</span>
                            <span>
                              <span className="text-white font-bold">EV-0{idx + 1}:</span> {sig}
                            </span>
                          </li>
                        ))
                      ) : (
                        <li className="flex items-start gap-2">
                          <span className="material-symbols-outlined text-white text-sm mt-0.5">check</span>
                          <span>EV-001: Nominal telemetry dynamics observed by ingestion pipeline.</span>
                        </li>
                      )}
                    </ul>
                  </div>

                  {/* Conflicting Signals */}
                  <div className="bg-[#080808] p-6 flex flex-col gap-4 border-l border-white shadow-[inset_2px_0_0_0_#ffffff]">
                    <div className="flex items-center justify-between border-b border-[#262626] pb-2">
                      <span className="font-label-caps text-label-caps text-white flex items-center gap-2">
                        <span className="material-symbols-outlined text-sm">warning</span>
                        CONFLICTING / COUNTER-SIGNALS
                      </span>
                      <span className="font-metadata text-metadata text-white px-2 py-0.5 bg-[#181818]">
                        UNCERTAINTY
                      </span>
                    </div>
                    <div className="bg-[#111111] p-4 border border-[#262626] flex flex-col gap-3">
                      <div className="flex justify-between items-center">
                        <span className="font-label-caps text-label-caps text-white">
                          {secExpl?.counter_evidence?.length ? 'OBSERVED COUNTER-EVIDENCE' : 'SUPPRESSING FACTORS'}
                        </span>
                      </div>
                      <p className="font-metadata text-metadata text-[#c6c6c6] leading-relaxed">
                        {secExpl?.counter_evidence?.[0] || 'Zero active signature detections or abnormal egress bursts observed.'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </section>
          </div>

          {/* Right Column (Span 4) */}
          <div className="col-span-12 xl:col-span-4 flex flex-col gap-gutter bg-[#262626]">
            {/* Evidence Weight */}
            <section className="bg-[#080808] p-6 relative group">
              <div className="absolute top-0 left-0 bg-[#181818] text-white font-label-caps text-label-caps px-3 py-1 flex items-center gap-2 border-b border-r border-[#262626]">
                <span className="material-symbols-outlined text-sm">balance</span>
                EVIDENCE WEIGHT
              </div>

              <div className="mt-8 flex flex-col gap-4">
                <div className="flex flex-col gap-1">
                  <div className="flex justify-between items-end">
                    <span className="font-metadata text-metadata text-[#8e9192] uppercase">Supporting</span>
                    <span className="font-label-caps text-label-caps text-white">0.74</span>
                  </div>
                  <div className="h-2 w-full bg-[#181818] flex">
                    <div className="h-full bg-white" style={{ width: '74%' }}></div>
                  </div>
                </div>
                <div className="flex flex-col gap-1">
                  <div className="flex justify-between items-end">
                    <span className="font-metadata text-metadata text-[#8e9192] uppercase">Conflicting</span>
                    <span className="font-label-caps text-label-caps text-[#8e9192]">0.21</span>
                  </div>
                  <div className="h-2 w-full bg-[#181818] flex">
                    <div className="h-full bg-[#8e9192]" style={{ width: '21%' }}></div>
                  </div>
                </div>
                <div className="flex flex-col gap-1">
                  <div className="flex justify-between items-end">
                    <span className="font-metadata text-metadata text-[#8e9192] uppercase">Unresolved</span>
                    <span className="font-label-caps text-label-caps text-[#444748]">0.05</span>
                  </div>
                  <div className="h-2 w-full bg-[#181818] flex">
                    <div className="h-full bg-[#353535]" style={{ width: '5%' }}></div>
                  </div>
                </div>
              </div>
            </section>

            {/* Provenance Chain (7 Steps) */}
            <section className="bg-[#080808] p-6 flex-1 relative group overflow-y-auto">
              <div className="absolute top-0 left-0 bg-[#181818] text-white font-label-caps text-label-caps px-3 py-1 flex items-center gap-2 border-b border-r border-[#262626]">
                <span className="material-symbols-outlined text-sm">schema</span>
                PROVENANCE CHAIN
              </div>
              <div className="absolute top-4 right-4 font-metadata text-metadata text-[#8e9192]">
                MODEL: AR(5) B4_AR_best(p=5)
              </div>

              <div className="mt-10 flex flex-col">
                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center mt-1">
                    <div className="w-3 h-3 bg-[#080808] border border-white"></div>
                    <div className="w-px h-8 bg-[#353535]"></div>
                  </div>
                  <div className="flex flex-col pb-4">
                    <span className="font-label-caps text-label-caps text-white">SOURCE</span>
                    <span className="font-metadata text-metadata text-[#8e9192]">T: 14:22:01.000 | RAW_PCAP</span>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center mt-1">
                    <div className="w-3 h-3 bg-[#080808] border border-[#c6c6c6]"></div>
                    <div className="w-px h-8 bg-[#353535]"></div>
                  </div>
                  <div className="flex flex-col pb-4">
                    <span className="font-label-caps text-label-caps text-[#c6c6c6]">COLLECTION</span>
                    <span className="font-metadata text-metadata text-[#8e9192]">INGEST_NODE_04 | 12ms</span>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center mt-1">
                    <div className="w-3 h-3 bg-[#080808] border border-[#c6c6c6]"></div>
                    <div className="w-px h-8 bg-[#353535]"></div>
                  </div>
                  <div className="flex flex-col pb-4">
                    <span className="font-label-caps text-label-caps text-[#c6c6c6]">NORMALIZATION</span>
                    <span className="font-metadata text-metadata text-[#8e9192]">SCHEMA_V2 | 45ms</span>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center mt-1">
                    <div className="w-3 h-3 bg-[#080808] border border-[#c6c6c6]"></div>
                    <div className="w-px h-8 bg-[#353535]"></div>
                  </div>
                  <div className="flex flex-col pb-4">
                    <span className="font-label-caps text-label-caps text-[#c6c6c6]">EXTRACTION</span>
                    <span className="font-metadata text-metadata text-[#8e9192]">NLP_PIPELINE | 102ms</span>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center mt-1">
                    <div className="w-3 h-3 bg-[#080808] border border-[#c6c6c6]"></div>
                    <div className="w-px h-8 bg-[#353535]"></div>
                  </div>
                  <div className="flex flex-col pb-4">
                    <span className="font-label-caps text-label-caps text-[#c6c6c6]">CORRELATION</span>
                    <span className="font-metadata text-metadata text-[#8e9192]">GRAPH_DB_MATCH | 215ms</span>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center mt-1">
                    <div className="w-3 h-3 bg-white border border-white"></div>
                    <div className="w-px h-8 bg-[#353535]"></div>
                  </div>
                  <div className="flex flex-col pb-4">
                    <span className="font-label-caps text-label-caps text-white">CASE ASSIGNMENT</span>
                    <span className="font-metadata text-metadata text-[#8e9192]">
                      {displayCaseId} | {liveEvent ? liveEvent.primary_stage : 'RULE_99A'}
                    </span>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center mt-1">
                    <div className="w-3 h-3 bg-[#080808] border border-[#353535] border-dashed"></div>
                  </div>
                  <div className="flex flex-col">
                    <span className="font-label-caps text-label-caps text-[#8e9192]">ATTRIBUTION</span>
                    <span className="font-metadata text-metadata text-[#8e9192]">PENDING_REVIEW</span>
                  </div>
                </div>
              </div>
            </section>

            {/* Analyst Review Panel */}
            <section className="bg-[#080808] p-6 relative group border border-transparent focus-within:border-white transition-colors">
              <div className="absolute top-0 left-0 bg-[#181818] text-white font-label-caps text-label-caps px-3 py-1 flex items-center gap-2 border-b border-r border-[#262626]">
                <span className="material-symbols-outlined text-sm">edit_note</span>
                ANALYST REVIEW
              </div>

              <div className="mt-8 flex flex-col gap-4 h-full">
                <div className="flex flex-col flex-1 relative">
                  <span className="absolute top-2 right-2 font-metadata text-metadata text-[#8e9192]">ACTIVE</span>
                  <textarea
                    value={analystNotes}
                    onChange={(e) => setAnalystNotes(e.target.value)}
                    rows={4}
                    className="w-full bg-[#111111] border border-[#262626] text-white font-metadata text-metadata p-3 focus:outline-none focus:border-white transition-colors resize-none placeholder:text-[#8e9192]"
                    placeholder="Enter analyst findings, correlation notes, or rationale for escalation..."
                  />
                </div>

                <div className="grid grid-cols-2 gap-2 mt-auto">
                  <button
                    onClick={handleMarkConflicting}
                    className="border border-[#262626] bg-transparent text-white font-label-caps text-label-caps py-2.5 px-3 hover:border-white transition-colors flex items-center justify-center gap-2 cursor-pointer"
                  >
                    MARK CONFLICTING
                  </button>
                  <button
                    onClick={handleRequestMoreEv}
                    className="border border-[#262626] bg-transparent text-white font-label-caps text-label-caps py-2.5 px-3 hover:border-white transition-colors flex items-center justify-center gap-2 cursor-pointer"
                  >
                    REQUEST MORE EV
                  </button>
                  <button
                    onClick={handleEscalate}
                    className="col-span-2 border border-[#353535] bg-[#111111] text-white font-label-caps text-label-caps py-2.5 px-4 hover:bg-[#181818] transition-colors flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-sm">priority_high</span> ESCALATE
                  </button>
                  <button
                    onClick={handleAcceptEvidence}
                    className="col-span-2 bg-white text-black font-label-caps text-label-caps py-2.5 px-4 hover:bg-[#c6c6c6] transition-colors flex items-center justify-center gap-2 mt-1 font-bold cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-sm">done_all</span> ACCEPT EVIDENCE
                  </button>
                </div>
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
};
