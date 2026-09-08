import React, { useState } from 'react';
import { useControlCenterStore } from '../../store/useControlCenterStore';
import { useRuntimeStore } from '../../store/useRuntimeStore';
import { INITIAL_ANALYSTS } from '../../data/mockData';
import { useNavigate } from 'react-router-dom';

export const TopAppBar: React.FC = () => {
  const { demoStatus, connectionState } = useRuntimeStore();
  const {
    systemMode,
    currentUser,
    setCurrentUser,
    setCommandPaletteOpen,
    setSystemMode,
    isNotificationDrawerOpen,
    setNotificationDrawerOpen,
    unreadNotificationsCount,
  } = useControlCenterStore();

  const [isRoleDropdownOpen, setIsRoleDropdownOpen] = useState(false);
  const [isStateDropdownOpen, setIsStateDropdownOpen] = useState(false);
  const navigate = useNavigate();

  return (
    <header className="flex justify-between items-center h-16 px-8 w-full z-30 bg-[#080808] border-b border-[#262626] flex-shrink-0">
      {/* Search on left */}
      <div className="flex items-center gap-4 w-1/3">
        <span className="material-symbols-outlined text-[#c6c6c6] text-[18px]">search</span>
        <button
          onClick={() => setCommandPaletteOpen(true)}
          className="bg-transparent border-none text-left text-[#c6c6c6] hover:text-white font-label-caps text-label-caps focus:outline-none w-full uppercase flex items-center justify-between cursor-pointer"
        >
          <span>SEARCH ENTITIES, CASES, EVIDENCE...</span>
          <span className="bg-[#181818] border border-[#262626] px-1.5 py-0.5 text-[9px] text-[#8e9192]">⌘ K</span>
        </button>
      </div>

      {/* Center Live Telemetry Links */}
      <div className="flex items-center gap-8 hidden xl:flex">
        {/* System status switcher */}
        <div className="relative">
          <button
            onClick={() => setIsStateDropdownOpen(!isStateDropdownOpen)}
            className={`flex items-center gap-2 font-label-caps text-label-caps uppercase cursor-pointer hover:text-white transition-colors ${
              systemMode === 'NORMAL' ? 'text-[#c6c6c6]' : 'text-[#F0C808] font-bold'
            }`}
          >
            <div
              className={`w-2 h-2 ${
                systemMode === 'NORMAL'
                  ? 'bg-white'
                  : 'bg-[#F0C808] animate-pulse'
              }`}
            ></div>
            <span>SYSTEM_STATUS: {systemMode}</span>
            <span className="material-symbols-outlined text-[14px]">expand_more</span>
          </button>

          {isStateDropdownOpen && (
            <div className="absolute top-full mt-2 left-0 w-44 bg-[#080808] border border-[#262626] shadow-2xl z-50 flex flex-col py-1">
              {(['NORMAL', 'DEGRADED', 'CRITICAL', 'RECOVERY'] as const).map((mode) => (
                <button
                  key={mode}
                  onClick={() => {
                    setSystemMode(mode);
                    setIsStateDropdownOpen(false);
                  }}
                  className={`px-3 py-2 text-left font-label-caps text-label-caps uppercase hover:bg-[#181818] flex items-center justify-between cursor-pointer ${
                    systemMode === mode ? 'text-[#F0C808] font-bold' : 'text-[#c6c6c6]'
                  }`}
                >
                  <span>{mode}</span>
                  {systemMode === mode && <span className="w-1.5 h-1.5 bg-[#F0C808]"></span>}
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="text-[#c6c6c6] font-label-caps text-label-caps uppercase flex items-center gap-2">
          <span
            className={`w-1.5 h-1.5 inline-block ${
              connectionState === 'CONNECTED'
                ? 'bg-[#FFD60A] animate-pulse'
                : connectionState === 'CONNECTING'
                ? 'bg-white'
                : 'bg-[#707070]'
            }`}
          ></span>
          <span>STREAM: {connectionState}</span>
        </div>
        <div className="text-[#c6c6c6] font-label-caps text-label-caps uppercase">
          DEMO: {demoStatus.status} {demoStatus.current_step >= 0 ? `(T${String(demoStatus.current_step).padStart(2, '0')})` : ''}
        </div>
      </div>

      {/* Trailing Actions */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => navigate('/command-center/system')}
          className="font-label-caps text-label-caps text-[#c6c6c6] hover:text-white uppercase border border-[#262626] px-3 py-1 hover:border-white transition-colors duration-150 cursor-pointer"
        >
          COMMAND_LOG
        </button>

        <div className="w-[1px] h-4 bg-[#262626] mx-1"></div>

        {/* Global Notification Bell with Yellow Badge */}
        <button
          onClick={() => setNotificationDrawerOpen(!isNotificationDrawerOpen)}
          title="Action Notifications"
          className="text-[#c6c6c6] hover:text-white transition-colors duration-150 cursor-pointer p-1.5 relative"
        >
          <span className="material-symbols-outlined text-[18px]">notifications</span>
          {unreadNotificationsCount > 0 && (
            <span className="absolute top-1 right-1 w-2 h-2 bg-[#F0C808] rounded-full"></span>
          )}
        </button>

        <button
          onClick={() => setCommandPaletteOpen(true)}
          title="Terminal Console"
          className="text-[#c6c6c6] hover:text-white transition-colors duration-150 cursor-pointer p-1.5"
        >
          <span className="material-symbols-outlined text-[18px]">terminal</span>
        </button>

        <button
          onClick={() => navigate('/command-center/settings')}
          title="Settings Workspace"
          className="text-[#c6c6c6] hover:text-white transition-colors duration-150 cursor-pointer p-1.5"
        >
          <span className="material-symbols-outlined text-[18px]">settings</span>
        </button>

        {/* User Identity & RBAC Role Switcher */}
        <div className="relative">
          <button
            onClick={() => setIsRoleDropdownOpen(!isRoleDropdownOpen)}
            className="flex items-center gap-2 ml-2 border border-[#262626] px-3 py-1 bg-[#111111] hover:border-white transition-colors cursor-pointer"
          >
            <div className="w-4 h-4 bg-white flex items-center justify-center">
              <span className="material-symbols-outlined text-[12px] text-black">person</span>
            </div>
            <span className="font-label-caps text-label-caps text-white uppercase">{currentUser.name}</span>
            <span className="material-symbols-outlined text-[14px] text-[#8e9192]">expand_more</span>
          </button>

          {isRoleDropdownOpen && (
            <div className="absolute right-0 top-full mt-2 w-56 bg-[#080808] border border-[#262626] shadow-2xl z-50 py-1">
              <div className="px-3 py-2 border-b border-[#181818]">
                <div className="font-metadata text-[9px] text-[#8e9192] uppercase">CURRENT RBAC CLEARANCE</div>
                <div className="font-label-caps text-label-caps text-white">{currentUser.clearance}</div>
              </div>
              {INITIAL_ANALYSTS.map((user) => (
                <button
                  key={user.id}
                  onClick={() => {
                    setCurrentUser(user);
                    setIsRoleDropdownOpen(false);
                  }}
                  className={`w-full px-3 py-2 text-left font-label-caps text-label-caps uppercase hover:bg-[#181818] flex items-center justify-between cursor-pointer ${
                    currentUser.id === user.id ? 'text-[#F0C808] font-bold' : 'text-[#c6c6c6]'
                  }`}
                >
                  <div className="flex flex-col">
                    <span>{user.name}</span>
                    <span className="text-[9px] text-[#8e9192] normal-case">{user.title}</span>
                  </div>
                  {currentUser.id === user.id && <span className="w-1.5 h-1.5 bg-[#F0C808]"></span>}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
