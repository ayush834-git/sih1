import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useControlCenterStore } from '../../store/useControlCenterStore';

export const CommandPalette: React.FC = () => {
  const { isCommandPaletteOpen, setCommandPaletteOpen, cases, entities, alerts } = useControlCenterStore();
  const [query, setQuery] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setCommandPaletteOpen(!isCommandPaletteOpen);
      }
      if (e.key === 'Escape' && isCommandPaletteOpen) {
        setCommandPaletteOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isCommandPaletteOpen, setCommandPaletteOpen]);

  if (!isCommandPaletteOpen) return null;

  const filteredCases = cases.filter(
    (c) => c.id.toLowerCase().includes(query.toLowerCase()) || c.title.toLowerCase().includes(query.toLowerCase())
  );
  const filteredEntities = entities.filter(
    (e) => e.name.toLowerCase().includes(query.toLowerCase()) || e.type.toLowerCase().includes(query.toLowerCase())
  );
  const filteredAlerts = alerts.filter(
    (a) => a.id.toLowerCase().includes(query.toLowerCase()) || a.type.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 bg-black/80 backdrop-blur-xs">
      <div className="w-full max-w-2xl bg-[#080808] border border-[#262626] shadow-2xl flex flex-col overflow-hidden">
        {/* Search Input */}
        <div className="flex items-center gap-3 p-4 border-b border-[#262626] bg-[#111111]">
          <span className="material-symbols-outlined text-[#c6c6c6] text-[20px]">search</span>
          <input
            autoFocus
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="SEARCH CASES, ENTITIES, ALERTS, COMMANDS..."
            className="flex-1 bg-transparent border-none text-white font-label-caps text-label-caps uppercase focus:outline-none placeholder:text-[#8e9192]"
          />
          <button
            onClick={() => setCommandPaletteOpen(false)}
            className="px-2 py-0.5 border border-[#353535] text-[10px] font-metadata text-[#8e9192] hover:text-white cursor-pointer"
          >
            ESC
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-96 overflow-y-auto p-2 flex flex-col gap-1 font-metadata text-metadata">
          {/* Quick Actions */}
          <div className="px-3 py-1 text-[10px] text-[#8e9192] uppercase font-label-caps border-b border-[#181818]">
            NAVIGATE & ACTIONS
          </div>
          <button
            onClick={() => {
              navigate('/command-center');
              setCommandPaletteOpen(false);
            }}
            className="flex items-center justify-between px-3 py-2 text-left hover:bg-[#181818] text-white cursor-pointer"
          >
            <span className="font-label-caps text-label-caps">GO TO OVERVIEW DASHBOARD</span>
            <span className="text-[#8e9192]">/command-center</span>
          </button>
          <button
            onClick={() => {
              navigate('/command-center/investigations');
              setCommandPaletteOpen(false);
            }}
            className="flex items-center justify-between px-3 py-2 text-left hover:bg-[#181818] text-white cursor-pointer"
          >
            <span className="font-label-caps text-label-caps">GO TO CASE INVESTIGATION WORKSPACE</span>
            <span className="text-[#8e9192]">CASE-019</span>
          </button>
          <button
            onClick={() => {
              navigate('/command-center/intelligence');
              setCommandPaletteOpen(false);
            }}
            className="flex items-center justify-between px-3 py-2 text-left hover:bg-[#181818] text-white cursor-pointer"
          >
            <span className="font-label-caps text-label-caps">GO TO ENTITY EXPLORER</span>
            <span className="text-[#8e9192]">GATEWAY_NODE_4</span>
          </button>
          <button
            onClick={() => {
              navigate('/command-center/evidence');
              setCommandPaletteOpen(false);
            }}
            className="flex items-center justify-between px-3 py-2 text-left hover:bg-[#181818] text-white cursor-pointer"
          >
            <span className="font-label-caps text-label-caps">GO TO EVIDENCE INTELLIGENCE</span>
            <span className="text-[#8e9192]">EV-00419</span>
          </button>
          <button
            onClick={() => {
              navigate('/command-center/system');
              setCommandPaletteOpen(false);
            }}
            className="flex items-center justify-between px-3 py-2 text-left hover:bg-[#181818] text-white cursor-pointer"
          >
            <span className="font-label-caps text-label-caps">GO TO SYSTEM HEALTH & AUDIT</span>
            <span className="text-[#8e9192]">AUDIT LOGS</span>
          </button>

          {/* Cases */}
          {filteredCases.length > 0 && (
            <>
              <div className="px-3 py-1 text-[10px] text-[#8e9192] uppercase font-label-caps border-b border-[#181818] mt-2">
                CASES
              </div>
              {filteredCases.map((c) => (
                <button
                  key={c.id}
                  onClick={() => {
                    navigate('/command-center/investigations');
                    setCommandPaletteOpen(false);
                  }}
                  className="flex items-center justify-between px-3 py-2 text-left hover:bg-[#181818] text-white cursor-pointer"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-label-caps text-[#F0C808]">{c.id}</span>
                    <span>{c.title}</span>
                  </div>
                  <span className="text-[#8e9192]">{c.attributionConfidence}% CONF</span>
                </button>
              ))}
            </>
          )}

          {/* Alerts */}
          {filteredAlerts.length > 0 && (
            <>
              <div className="px-3 py-1 text-[10px] text-[#8e9192] uppercase font-label-caps border-b border-[#181818] mt-2">
                ALERTS
              </div>
              {filteredAlerts.map((a) => (
                <button
                  key={a.id}
                  onClick={() => {
                    navigate('/command-center/alerts');
                    setCommandPaletteOpen(false);
                  }}
                  className="flex items-center justify-between px-3 py-2 text-left hover:bg-[#181818] text-white cursor-pointer"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-label-caps text-[#F0C808]">{a.id}</span>
                    <span>{a.type}</span>
                  </div>
                  <span className="text-[#8e9192]">{a.confidence}% CONF</span>
                </button>
              ))}
            </>
          )}

          {/* Entities */}
          {filteredEntities.length > 0 && (
            <>
              <div className="px-3 py-1 text-[10px] text-[#8e9192] uppercase font-label-caps border-b border-[#181818] mt-2">
                ENTITIES
              </div>
              {filteredEntities.map((e) => (
                <button
                  key={e.id}
                  onClick={() => {
                    navigate('/command-center/intelligence');
                    setCommandPaletteOpen(false);
                  }}
                  className="flex items-center justify-between px-3 py-2 text-left hover:bg-[#181818] text-white cursor-pointer"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-metadata text-white">{e.name}</span>
                    <span className="text-[9px] bg-[#181818] px-1 border border-[#262626] text-[#c6c6c6]">{e.type}</span>
                  </div>
                  <span className="text-[#8e9192]">{e.observationsCount} OBS</span>
                </button>
              ))}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-[#262626] bg-[#000001] flex justify-between items-center text-[10px] text-[#8e9192] font-metadata">
          <span>USE ARROW KEYS OR CLICK TO SELECT</span>
          <span>CONTROL CENTRE v2.0.4</span>
        </div>
      </div>
    </div>
  );
};
