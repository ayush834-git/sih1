import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useControlCenterStore } from '../../store/useControlCenterStore';

export const SideNavBar: React.FC = () => {
  const { currentUser, setActiveCaseId } = useControlCenterStore();
  const navigate = useNavigate();

  const handleNewInvestigation = () => {
    setActiveCaseId('CASE-019');
    navigate('/command-center/investigations');
  };

  return (
    <aside className="fixed left-0 top-0 h-full w-[240px] flex flex-col border-r border-[#262626] z-40 bg-[#080808] text-[#ffffff]">
      {/* Header */}
      <div className="p-8 border-b border-[#262626] flex flex-col gap-2">
        <div className="w-8 h-8 bg-white flex items-center justify-center">
          <span className="material-symbols-outlined text-[#080808] text-[20px]">blur_on</span>
        </div>
        <div className="mt-4">
          <h1 className="font-headline-lg text-headline-lg font-black text-white uppercase tracking-tighter leading-none text-[22px]">
            CONTROL CENTRE
          </h1>
          <p className="font-metadata text-metadata text-[#c6c6c6] mt-2">V2.0.4-STABLE</p>
        </div>
      </div>

      {/* CTA */}
      <div className="p-4 border-b border-[#262626]">
        <button
          onClick={handleNewInvestigation}
          className="w-full bg-white text-[#080808] font-label-caps text-label-caps py-2 border border-transparent hover:bg-transparent hover:border-white hover:text-white transition-colors duration-150 flex items-center justify-center gap-2 cursor-pointer font-bold"
        >
          <span className="material-symbols-outlined text-[16px]">add</span>
          NEW_INVESTIGATION
        </button>
      </div>

      {/* Navigation Tabs */}
      <nav className="flex-1 overflow-y-auto py-4 flex flex-col gap-[1px]">
        <NavLink
          to="/command-center"
          end
          className={({ isActive }) =>
            `flex items-center gap-4 px-8 py-3 text-label-caps transition-all duration-75 uppercase ${
              isActive
                ? 'text-white font-bold bg-[#181818] border-l-2 border-white'
                : 'text-[#c6c6c6] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`
          }
        >
          <span className="material-symbols-outlined text-[20px]">dashboard</span>
          <span>OVERVIEW</span>
        </NavLink>

        <NavLink
          to="/command-center/investigations"
          className={({ isActive }) =>
            `flex items-center gap-4 px-8 py-3 text-label-caps transition-all duration-75 uppercase ${
              isActive
                ? 'text-white font-bold bg-[#181818] border-l-2 border-white'
                : 'text-[#c6c6c6] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`
          }
        >
          <span className="material-symbols-outlined text-[20px]">security</span>
          <span>INVESTIGATIONS</span>
        </NavLink>

        <NavLink
          to="/command-center/intelligence"
          className={({ isActive }) =>
            `flex items-center gap-4 px-8 py-3 text-label-caps transition-all duration-75 uppercase ${
              isActive
                ? 'text-white font-bold bg-[#181818] border-l-2 border-white'
                : 'text-[#c6c6c6] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`
          }
        >
          <span className="material-symbols-outlined text-[20px]">hub</span>
          <span>INTELLIGENCE</span>
        </NavLink>

        <NavLink
          to="/command-center/evidence"
          className={({ isActive }) =>
            `flex items-center gap-4 px-8 py-3 text-label-caps transition-all duration-75 uppercase ${
              isActive
                ? 'text-white font-bold bg-[#181818] border-l-2 border-white'
                : 'text-[#c6c6c6] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`
          }
        >
          <span className="material-symbols-outlined text-[20px]">plagiarism</span>
          <span>EVIDENCE</span>
        </NavLink>

        <NavLink
          to="/command-center/alerts"
          className={({ isActive }) =>
            `flex items-center gap-4 px-8 py-3 text-label-caps transition-all duration-75 uppercase ${
              isActive
                ? 'text-white font-bold bg-[#181818] border-l-2 border-white'
                : 'text-[#c6c6c6] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`
          }
        >
          <span className="material-symbols-outlined text-[20px]">notifications_active</span>
          <span>ALERTS</span>
        </NavLink>

        <NavLink
          to="/command-center/system"
          className={({ isActive }) =>
            `flex items-center gap-4 px-8 py-3 text-label-caps transition-all duration-75 uppercase ${
              isActive
                ? 'text-white font-bold bg-[#181818] border-l-2 border-white'
                : 'text-[#c6c6c6] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`
          }
        >
          <span className="material-symbols-outlined text-[20px]">analytics</span>
          <span>SYSTEM</span>
        </NavLink>

        <NavLink
          to="/command-center/simulation"
          className={({ isActive }) =>
            `flex items-center gap-4 px-8 py-3 text-label-caps transition-all duration-75 uppercase ${
              isActive
                ? 'text-white font-bold bg-[#181818] border-l-2 border-white'
                : 'text-[#c6c6c6] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`
          }
        >
          <span className="material-symbols-outlined text-[20px]">play_circle</span>
          <span>SIMULATION</span>
        </NavLink>
      </nav>

      {/* Footer Tabs */}
      <div className="border-t border-[#262626] py-2 flex flex-col gap-[1px]">
        <div className="px-8 py-3 flex items-center gap-3 border-b border-[#181818]">
          <div className="w-5 h-5 bg-[#353535] flex items-center justify-center">
            <span className="material-symbols-outlined text-[14px] text-white">person</span>
          </div>
          <div className="flex flex-col">
            <span className="font-label-caps text-[10px] text-white uppercase">{currentUser.name}</span>
            <span className="font-metadata text-[9px] text-[#8e9192] uppercase">{currentUser.clearance}</span>
          </div>
        </div>

        <NavLink
          to="/command-center/settings"
          className={({ isActive }) =>
            `flex items-center gap-4 px-8 py-2 text-label-caps transition-all duration-75 uppercase ${
              isActive
                ? 'text-white font-bold bg-[#181818] border-l-2 border-white'
                : 'text-[#c6c6c6] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`
          }
        >
          <span className="material-symbols-outlined text-[18px]">settings</span>
          <span>SETTINGS</span>
        </NavLink>
        <button
          onClick={() => window.open('https://github.com', '_blank')}
          className="flex items-center gap-4 px-8 py-2 text-[#c6c6c6] hover:text-white hover:bg-[#111111] transition-all duration-75 text-left cursor-pointer"
        >
          <span className="material-symbols-outlined text-[18px]">help_outline</span>
          <span className="font-label-caps text-label-caps uppercase">HELP</span>
        </button>
      </div>
    </aside>
  );
};
