import React, { useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import { SideNavBar } from './SideNavBar';
import { TopAppBar } from './TopAppBar';
import { CommandPalette } from '../common/CommandPalette';
import { ManualOverrideModal } from '../common/ManualOverrideModal';
import { NotificationDrawer } from '../common/NotificationDrawer';
import { useRuntimeStore } from '../../store/useRuntimeStore';

export const ControlCenterLayout: React.FC = () => {
  const { initRuntime } = useRuntimeStore();

  useEffect(() => {
    initRuntime();
  }, []);
  return (
    <div className="bg-[#000001] text-white min-h-screen flex antialiased selection:bg-[#F0C808] selection:text-black">
      {/* 240px Fixed Sidebar */}
      <SideNavBar />

      {/* Main Content Area */}
      <div className="flex-1 ml-[240px] flex flex-col min-h-screen bg-[#000001] relative z-10 overflow-hidden">
        {/* Top Navigation Bar */}
        <TopAppBar />

        {/* Dynamic Nested Screen Route */}
        <main className="flex-1 overflow-y-auto bg-[#000001] flex flex-col relative">
          <Outlet />
        </main>
      </div>

      {/* Global Modals & Drawers */}
      <CommandPalette />
      <ManualOverrideModal />
      <NotificationDrawer />
    </div>
  );
};
