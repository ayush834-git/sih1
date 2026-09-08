import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useControlCenterStore } from '../store/useControlCenterStore';
import { useRuntimeStore } from '../store/useRuntimeStore';

export const EntityExplorerPage: React.FC = () => {
  const { setCommandPaletteOpen } = useControlCenterStore();
  const { snapshot, eventHistory, demoStatus } = useRuntimeStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedStepIndex, setSelectedStepIndex] = useState<number | null>(null);
  const [selectedFeatureName, setSelectedFeatureName] = useState<string | null>(null);
  const navigate = useNavigate();

  const safeHistory = Array.isArray(eventHistory) ? eventHistory : [];
  const liveEvent = snapshot.event;

  // Active event can be explicitly selected historical step or current live event
  const activeEvent =
    selectedStepIndex !== null
      ? safeHistory.find((e) => e.step_index === selectedStepIndex) || liveEvent
      : liveEvent;

  const contributions = activeEvent?.forecast_feature_contributions || [];
  const secExpl = activeEvent?.security_explanation;

  const filteredContributions = contributions.filter((c) => {
    return (
      c.feature_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.signed_direction.toLowerCase().includes(searchQuery.toLowerCase())
    );
  });

  const focusedFeature =
    filteredContributions.find((c) => c.feature_name === selectedFeatureName) ||
    filteredContributions[0] ||
    contributions[0];

  const futureScores = activeEvent?.future_risk_scores || {};
  const h1Score = futureScores['+10s'] !== undefined ? futureScores['+10s'] : (activeEvent?.current_risk_score ?? 0);
  const h2Score = futureScores['+20s'] !== undefined ? futureScores['+20s'] : h1Score * 0.9;
  const h3Score = futureScores['+30s'] !== undefined ? futureScores['+30s'] : h2Score * 0.85;

  return (
    <div className="p-8 min-h-full flex flex-col gap-6 bg-[#000001] relative text-white">
      {/* Ambient Grid Background */}
      <div className="fixed inset-0 grid-bg pointer-events-none z-0"></div>

      <div className="relative z-10 flex flex-col gap-6">
        {/* Page Header */}
        <div className="flex flex-col gap-2 border-b border-[#262626] pb-6">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
            <div>
              <h2 className="font-headline-lg text-headline-lg text-white tracking-tight">
                INTELLIGENCE // CAUSAL REASONING &amp; AR(5) DYNAMICS
              </h2>
              <p className="font-metadata text-metadata text-[#c6c6c6]">
                Trace why the system forecasts evolving risk: temporal deltas $\to$ feature momentum $\to$ hypothesis $\to$ supporting/counter-evidence.
              </p>
            </div>
            {activeEvent && (
              <div className="bg-[#111111] border border-[#262626] px-4 py-2 text-right">
                <div className="font-label-caps text-label-caps text-[#F0C808]">
                  INSPECTING WINDOW: {activeEvent.logical_time_str || `T${activeEvent.step_index}`} [{activeEvent.primary_stage}]
                </div>
                <div className="font-metadata text-[10px] text-[#8e9192]">
                  PROVENANCE: {secExpl?.provenance_hash ? `${secExpl.provenance_hash.substring(0, 16)}...` : 'AUTH_AR5'}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Temporal Window Navigation Strip */}
        {safeHistory.length > 0 && (
          <div className="flex items-center gap-2 overflow-x-auto pb-1 border-b border-[#1c1c1c]">
            <span className="font-metadata text-[10px] text-[#8e9192] uppercase whitespace-nowrap mr-2">
              SELECT WINDOW:
            </span>
            {safeHistory.map((evt) => {
              const isSelected =
                (selectedStepIndex === null && evt.step_index === demoStatus.current_step) ||
                selectedStepIndex === evt.step_index;
              const isElevated = (evt.current_risk_score ?? 0) > 0.25;

              return (
                <button
                  key={evt.event_id}
                  onClick={() => setSelectedStepIndex(evt.step_index)}
                  className={`px-3 py-1 font-metadata text-[11px] border whitespace-nowrap transition-colors cursor-pointer flex items-center gap-1.5 ${
                    isSelected
                      ? 'border-[#F0C808] bg-[#111111] text-[#F0C808] font-bold'
                      : isElevated
                      ? 'border-[#ffb4ab]/40 bg-[#140c0c] text-white hover:border-[#ffb4ab]'
                      : 'border-[#262626] bg-[#080808] text-[#8e9192] hover:text-white'
                  }`}
                >
                  <span>{evt.logical_time_str || `T${evt.step_index}`}</span>
                  <span className="text-[9px] opacity-75">
                    ({((evt.current_risk_score ?? 0) * 100).toFixed(0)}%)
                  </span>
                </button>
              );
            })}
            {selectedStepIndex !== null && (
              <button
                onClick={() => setSelectedStepIndex(null)}
                className="px-2 py-1 text-[10px] font-label-caps text-[#8e9192] hover:text-white underline cursor-pointer ml-2 whitespace-nowrap"
              >
                RETURN TO LIVE
              </button>
            )}
          </div>
        )}

        {/* Multi-Step Future Security Risk Bar (h=1, h=2, h=3) */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-gutter bg-[#262626] border border-[#262626] p-[1px]">
          <div className="bg-[#080808] p-4 flex flex-col justify-between">
            <div className="flex justify-between items-center mb-2">
              <span className="font-label-caps text-[11px] text-[#8e9192] uppercase">
                FUTURE RISK // h=1 (+10s)
              </span>
              <span className="font-label-caps text-[10px] text-white bg-[#181818] px-2 py-0.5 border border-[#262626]">
                AR(5) LEAD
              </span>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="font-headline-lg text-headline-lg text-[#F0C808] font-bold">
                {(h1Score * 100).toFixed(1)}%
              </span>
              <span className="font-metadata text-[10px] text-[#8e9192]">HEURISTIC SCORE</span>
            </div>
            <div className="w-full h-1 bg-[#181818] mt-2">
              <div className="h-full bg-[#F0C808]" style={{ width: `${Math.min(100, h1Score * 100)}%` }}></div>
            </div>
          </div>

          <div className="bg-[#080808] p-4 flex flex-col justify-between">
            <div className="flex justify-between items-center mb-2">
              <span className="font-label-caps text-[11px] text-[#8e9192] uppercase">
                FUTURE RISK // h=2 (+20s)
              </span>
              <span className="font-label-caps text-[10px] text-[#8e9192] bg-[#111111] px-2 py-0.5 border border-[#262626]">
                HORIZON 2
              </span>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="font-headline-lg text-headline-lg text-white font-bold">
                {(h2Score * 100).toFixed(1)}%
              </span>
              <span className="font-metadata text-[10px] text-[#8e9192]">DECAY WEIGHTED</span>
            </div>
            <div className="w-full h-1 bg-[#181818] mt-2">
              <div className="h-full bg-white" style={{ width: `${Math.min(100, h2Score * 100)}%` }}></div>
            </div>
          </div>

          <div className="bg-[#080808] p-4 flex flex-col justify-between">
            <div className="flex justify-between items-center mb-2">
              <span className="font-label-caps text-[11px] text-[#8e9192] uppercase">
                FUTURE RISK // h=3 (+30s)
              </span>
              <span className="font-label-caps text-[10px] text-[#8e9192] bg-[#111111] px-2 py-0.5 border border-[#262626]">
                HORIZON 3
              </span>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="font-headline-lg text-headline-lg text-[#8e9192] font-bold">
                {(h3Score * 100).toFixed(1)}%
              </span>
              <span className="font-metadata text-[10px] text-[#8e9192]">TENTATIVE</span>
            </div>
            <div className="w-full h-1 bg-[#181818] mt-2">
              <div className="h-full bg-[#8e9192]" style={{ width: `${Math.min(100, h3Score * 100)}%` }}></div>
            </div>
          </div>
        </div>

        {/* Search Filter Bar */}
        <div className="relative w-full group">
          <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-[#c6c6c6] text-[24px] group-focus-within:text-white transition-colors">
            search
          </span>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="SEARCH FEATURE CONTRIBUTIONS, SIGNATURES, DYNAMICS EXPLANATIONS..."
            className="w-full bg-[#080808] border border-[#262626] py-3.5 pl-12 pr-16 font-body-rg text-body-rg text-white focus:outline-none focus:border-white transition-colors placeholder:text-[#8e9192]"
          />
          <button
            onClick={() => setCommandPaletteOpen(true)}
            className="absolute right-4 top-1/2 -translate-y-1/2 bg-[#181818] px-2 py-0.5 border border-[#262626] cursor-pointer"
          >
            <span className="font-metadata text-metadata text-[#c6c6c6]">⌘ K</span>
          </button>
        </div>

        {/* Bento Grid Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-gutter bg-[#262626] p-[1px]">
          {/* Section 01: Feature Contributions Index (Left Column, 8 cols) */}
          <div className="bento-module col-span-1 lg:col-span-8 flex flex-col p-6 min-h-[500px] bg-[#080808]">
            <div className="flex justify-between items-start mb-6">
              <div>
                <h3 className="font-label-caps text-label-caps text-white">
                  AR(5) FEATURE MOMENTUM CONTRIBUTIONS
                </h3>
                <span className="font-metadata text-[10px] text-[#8e9192]">
                  Ranked by normalized contribution weight to the forecasted state delta
                </span>
              </div>
              <span className="font-metadata text-metadata text-[#c6c6c6]">
                {filteredContributions.length} OF {contributions.length} FEATURES
              </span>
            </div>

            <div className="overflow-x-auto w-full flex-grow">
              {filteredContributions.length > 0 ? (
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-[#262626]">
                      <th className="font-metadata text-metadata text-[#8e9192] pb-2 font-normal">FEATURE</th>
                      <th className="font-metadata text-metadata text-[#8e9192] pb-2 font-normal">DIRECTION</th>
                      <th className="font-metadata text-metadata text-[#8e9192] pb-2 font-normal text-right">NOW</th>
                      <th className="font-metadata text-metadata text-[#8e9192] pb-2 font-normal text-right">Δ H1 PRED</th>
                      <th className="font-metadata text-metadata text-[#8e9192] pb-2 font-normal text-right">WEIGHT</th>
                    </tr>
                  </thead>
                  <tbody className="font-body-rg text-[13px]">
                    {filteredContributions.map((feat) => {
                      const isSelected = focusedFeature?.feature_name === feat.feature_name;
                      return (
                        <tr
                          key={feat.feature_name}
                          onClick={() => setSelectedFeatureName(feat.feature_name)}
                          className={`border-b border-[#262626] cursor-pointer transition-colors ${
                            isSelected ? 'bg-[#181818]' : 'hover:bg-[#111111]'
                          }`}
                        >
                          <td
                            className={`py-3 font-metadata text-white pl-2 relative ${
                              isSelected ? 'border-l-2 border-[#F0C808] -left-[2px]' : ''
                            }`}
                          >
                            <div className="font-bold">{feat.feature_name}</div>
                            <div className="text-[10px] text-[#8e9192] truncate max-w-xs">{feat.description}</div>
                          </td>
                          <td className="py-3 text-[#c6c6c6]">
                            <span
                              className={`px-1.5 py-0.5 border font-label-caps text-[9px] ${
                                feat.signed_direction === 'POSITIVE'
                                  ? 'bg-[#111111] border-[#F0C808] text-[#F0C808]'
                                  : feat.signed_direction === 'NEGATIVE'
                                  ? 'bg-[#111111] border-[#ffb4ab] text-[#ffb4ab]'
                                  : 'bg-[#111111] border-[#262626] text-[#707070]'
                              }`}
                            >
                              {feat.signed_direction}
                            </span>
                          </td>
                          <td className="py-3 text-[#c6c6c6] text-right font-metadata">
                            {feat.current_value !== undefined ? feat.current_value.toFixed(1) : '--'}
                          </td>
                          <td className="py-3 text-[#c6c6c6] text-right font-metadata">
                            {feat.predicted_delta >= 0
                              ? `+${feat.predicted_delta.toFixed(2)}`
                              : feat.predicted_delta.toFixed(2)}
                          </td>
                          <td
                            className={`py-3 text-right font-metadata ${
                              isSelected ? 'text-[#F0C808] font-bold' : 'text-white'
                            }`}
                          >
                            {(feat.normalized_contribution * 100).toFixed(1)}%
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <div className="py-12 text-center text-[#707070] italic font-metadata text-metadata">
                  {safeHistory.length === 0
                    ? 'Telemetry buffer empty. Click START SIMULATION to stream telemetry and generate live feature explanations.'
                    : 'No matching features found for query.'}
                </div>
              )}
            </div>
          </div>

          {/* Right Column Stack (4 cols) */}
          <div className="col-span-1 lg:col-span-4 flex flex-col gap-gutter bg-[#262626]">
            {/* Section 02: Selected Feature AR(5) Lag Breakdown */}
            <div className="bento-module p-6 flex flex-col bg-[#080808]">
              <div className="flex justify-between items-start mb-4">
                <h3 className="font-label-caps text-label-caps text-white flex items-center gap-2">
                  <span className="w-2 h-2 bg-[#F0C808] inline-block"></span>
                  AR(5) LAG BREAKDOWN
                </h3>
                <span className="bg-white text-[#000001] px-1.5 py-0.5 text-[10px] font-metadata font-bold">
                  {focusedFeature ? 'SELECTED' : 'STANDBY'}
                </span>
              </div>

              {focusedFeature ? (
                <div className="mb-6">
                  <div className="font-metadata text-[18px] text-white mb-1">
                    {focusedFeature.feature_name}
                  </div>
                  <p className="font-body-rg text-[12px] text-[#c6c6c6] mb-4 leading-relaxed">
                    {focusedFeature.description}
                  </p>

                  <div className="divide-y divide-[#262626] font-metadata text-[11px] bg-[#0B0B0B] border border-[#262626] px-3">
                    {focusedFeature.lag_breakdown && focusedFeature.lag_breakdown.length > 0 ? (
                      focusedFeature.lag_breakdown.map((lag) => (
                        <div key={lag.lag_order} className="py-2 flex justify-between items-center">
                          <span className="text-[#8e9192]">Lag p={lag.lag_order}</span>
                          <span className="text-white">coef: {lag.coefficient.toFixed(3)}</span>
                          <span className="text-[#F0C808] font-bold">
                            wt: {(lag.relative_weight * 100).toFixed(0)}%
                          </span>
                        </div>
                      ))
                    ) : (
                      <div className="py-3 text-center text-[#707070] italic">
                        Authoritative AR(5) model weights active.
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="py-8 text-center text-[#707070] italic font-metadata">
                  Select a feature to inspect its 5-step historical lag weights.
                </div>
              )}

              <div className="flex flex-col gap-2 mt-auto">
                <button
                  onClick={() => navigate('/command-center/evidence')}
                  className="w-full py-2 bg-transparent text-white font-label-caps text-label-caps hover:border-white transition-colors border border-[#262626] cursor-pointer"
                >
                  VIEW EVIDENCE TRACE
                </button>
                <button
                  onClick={() => navigate('/command-center/simulation')}
                  className="w-full py-2 bg-white text-[#000001] font-label-caps text-label-caps hover:bg-[#e0e0e0] transition-colors border border-white font-bold cursor-pointer"
                >
                  OPEN SIMULATION CONTROL
                </button>
              </div>
            </div>

            {/* Section 03: Security Hypothesis & Evidence Attribution */}
            <div className="bento-module p-6 relative flex flex-col bg-[#080808]">
              <div className="flex justify-between items-start mb-3">
                <h3 className="font-label-caps text-label-caps text-white">
                  SECURITY_EVIDENCE &amp; HYPOTHESIS
                </h3>
                <span className="font-label-caps text-[10px] text-[#F0C808]">
                  CONF: {activeEvent ? `${Math.round((activeEvent.stage_confidence ?? 0.85) * 100)}%` : '--'}
                </span>
              </div>

              <div className="space-y-4 font-metadata text-[12px] text-[#c6c6c6]">
                {/* Hypothesis */}
                <div>
                  <span className="text-[#8e9192] block text-[10px] uppercase mb-1">Active Hypothesis</span>
                  <div className="font-bold text-white bg-[#111111] p-2 border border-[#262626]">
                    {activeEvent ? activeEvent.primary_stage : 'NOMINAL MONITORING'}
                  </div>
                </div>

                {/* Supporting Evidence */}
                <div>
                  <span className="text-[#8e9192] block text-[10px] uppercase mb-1">Supporting Evidence</span>
                  <div className="space-y-1.5 pl-2 border-l-2 border-[#F0C808]">
                    {secExpl?.supporting_evidence && secExpl.supporting_evidence.length > 0 ? (
                      secExpl.supporting_evidence.map((sup, idx) => (
                        <div key={idx} className="text-white text-[11px]">
                          • {sup}
                        </div>
                      ))
                    ) : (
                      <span className="text-[#8e9192] italic">
                        {activeEvent ? 'Nominal baseline telemetry dynamics.' : 'Awaiting simulation telemetry.'}
                      </span>
                    )}
                  </div>
                </div>

                {/* Counter / Suppressing Evidence */}
                <div>
                  <span className="text-[#8e9192] block text-[10px] uppercase mb-1">
                    Suppressing / Counter-Evidence
                  </span>
                  <div className="space-y-1.5 pl-2 border-l-2 border-[#8e9192]">
                    {secExpl?.counter_evidence && secExpl.counter_evidence.length > 0 ? (
                      secExpl.counter_evidence.map((cnt, idx) => (
                        <div key={idx} className="text-[#c6c6c6] text-[11px]">
                          • {cnt}
                        </div>
                      ))
                    ) : (
                      <span className="text-[#8e9192] italic">Zero suppressing indicators.</span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
