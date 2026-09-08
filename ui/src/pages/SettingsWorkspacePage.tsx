import React, { useState } from 'react';
import { useControlCenterStore } from '../store/useControlCenterStore';

export const SettingsWorkspacePage: React.FC = () => {
  const { currentUser, userRegistry, sessions, revokeSession } = useControlCenterStore();
  const [activeTab, setActiveTab] = useState<'PROFILE' | 'ACCESS' | 'SESSIONS' | 'DEFAULTS' | 'NOTIFICATIONS'>('PROFILE');
  const [notification, setNotification] = useState<string | null>(null);

  const handleRevoke = (sessionId: string) => {
    revokeSession(sessionId);
    setNotification(`SESSION ${sessionId} REVOKED SUCCESSFULLY`);
    setTimeout(() => setNotification(null), 3000);
  };

  return (
    <div className="flex flex-1 h-full overflow-hidden bg-[#000001] text-white">
      {/* Toast Notification */}
      {notification && (
        <div className="absolute top-4 right-8 z-50 bg-[#111111] border border-[#F0C808] text-[#F0C808] px-4 py-2 font-label-caps text-label-caps flex items-center gap-2 shadow-2xl animate-fade-in">
          <span className="material-symbols-outlined text-[18px]">verified</span>
          <span>{notification}</span>
        </div>
      )}

      {/* Settings Side Nav */}
      <aside className="w-64 border-r border-[#262626] bg-[#080808] flex-shrink-0 flex flex-col h-full overflow-y-auto">
        <div className="p-6 border-b border-[#262626]">
          <h2 className="font-label-caps text-label-caps text-white uppercase">SETTINGS</h2>
          <p className="font-metadata text-metadata text-[#8e9192] mt-1">WORKSPACE CONFIGURATION</p>
        </div>
        <nav className="flex-1 flex flex-col py-3">
          <button
            onClick={() => setActiveTab('PROFILE')}
            className={`px-6 py-3 font-label-caps text-label-caps flex items-center gap-3 transition-colors text-left cursor-pointer ${
              activeTab === 'PROFILE'
                ? 'bg-[#181818] text-white font-bold border-l-2 border-[#F0C808]'
                : 'text-[#8e9192] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`}
          >
            <span>PROFILE</span>
          </button>
          <button
            onClick={() => setActiveTab('ACCESS')}
            className={`px-6 py-3 font-label-caps text-label-caps flex items-center gap-3 transition-colors text-left cursor-pointer ${
              activeTab === 'ACCESS'
                ? 'bg-[#181818] text-white font-bold border-l-2 border-[#F0C808]'
                : 'text-[#8e9192] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`}
          >
            <span>ACCESS CONTROL</span>
          </button>
          <button
            onClick={() => setActiveTab('SESSIONS')}
            className={`px-6 py-3 font-label-caps text-label-caps flex items-center gap-3 transition-colors text-left cursor-pointer ${
              activeTab === 'SESSIONS'
                ? 'bg-[#181818] text-white font-bold border-l-2 border-[#F0C808]'
                : 'text-[#8e9192] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`}
          >
            <span>ACTIVE SESSIONS</span>
          </button>
          <button
            onClick={() => setActiveTab('NOTIFICATIONS')}
            className={`px-6 py-3 font-label-caps text-label-caps flex items-center gap-3 transition-colors text-left cursor-pointer ${
              activeTab === 'NOTIFICATIONS'
                ? 'bg-[#181818] text-white font-bold border-l-2 border-[#F0C808]'
                : 'text-[#8e9192] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`}
          >
            <span>NOTIFICATIONS</span>
          </button>
          <button
            onClick={() => setActiveTab('DEFAULTS')}
            className={`px-6 py-3 font-label-caps text-label-caps flex items-center gap-3 transition-colors text-left cursor-pointer ${
              activeTab === 'DEFAULTS'
                ? 'bg-[#181818] text-white font-bold border-l-2 border-[#F0C808]'
                : 'text-[#8e9192] hover:text-white hover:bg-[#111111] border-l-2 border-transparent'
            }`}
          >
            <span>INVESTIGATION DEFAULTS</span>
          </button>
        </nav>
      </aside>

      {/* Settings Content Panel */}
      <main className="flex-1 p-8 overflow-y-auto bg-[#000001]">
        <div className="max-w-5xl mx-auto space-y-8">
          {/* TAB 1: PROFILE */}
          {activeTab === 'PROFILE' && (
            <div className="space-y-6 animate-fade-in">
              <div>
                <h1 className="font-headline-lg text-headline-lg text-white uppercase">PROFILE</h1>
                <p className="font-metadata text-metadata text-[#8e9192] mt-2 max-w-xl">
                  Configure operational parameters and review active session telemetry for the current investigator profile.
                </p>
              </div>

              <div className="grid grid-cols-12 gap-gutter bg-[#262626] border border-[#262626]">
                <div className="col-span-12 bg-[#080808] p-8 relative group">
                  <div className="flex justify-between items-start mb-6 border-b border-[#262626] pb-4">
                    <h3 className="font-label-caps text-label-caps text-white uppercase">IDENTITY PARAMETERS</h3>
                    <span className="font-metadata text-metadata text-[#8e9192]">ID_SYS_019</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                    <div className="flex flex-col gap-1">
                      <span className="font-metadata text-metadata text-[#8e9192] uppercase">Analyst Name</span>
                      <span className="font-body-rg text-[16px] text-white uppercase font-bold">{currentUser.name}</span>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="font-metadata text-metadata text-[#8e9192] uppercase">Role Definition</span>
                      <span className="font-body-rg text-[16px] text-white uppercase">{currentUser.title}</span>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="font-metadata text-metadata text-[#8e9192] uppercase">Session Time</span>
                      <span className="font-metadata text-metadata text-white uppercase">14:42 UTC</span>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="font-metadata text-metadata text-[#8e9192] uppercase">Authentication</span>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="w-2 h-2 bg-[#F0C808] inline-block"></span>
                        <span className="font-metadata text-metadata text-[#F0C808] uppercase font-bold">MFA_ACTIVE</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="col-span-12 bg-[#080808] p-8">
                  <h3 className="font-label-caps text-label-caps text-white uppercase mb-4">SECURITY CLEARANCE</h3>
                  <div className="bg-[#111111] p-4 border border-[#262626] flex justify-between items-center">
                    <div>
                      <div className="font-label-caps text-label-caps text-[#F0C808]">{currentUser.clearance}</div>
                      <div className="font-metadata text-metadata text-[#8e9192] mt-1">
                        Full biometric access granted for Level-5 intelligence assets and containment commands.
                      </div>
                    </div>
                    <span className="material-symbols-outlined text-[#F0C808] text-2xl">verified_user</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: ACCESS CONTROL */}
          {activeTab === 'ACCESS' && (
            <div className="space-y-6 animate-fade-in">
              <div>
                <h1 className="font-headline-lg text-headline-lg text-white uppercase">ACCESS MANAGEMENT</h1>
                <p className="font-metadata text-metadata text-[#8e9192] mt-2 max-w-xl">
                  User directory registry, role definitions, and live authorization audit log.
                </p>
              </div>

              <div className="grid grid-cols-12 gap-gutter bg-[#262626] border border-[#262626]">
                {/* USER REGISTRY TABLE (8 cols) */}
                <section className="col-span-12 lg:col-span-8 bg-[#080808] p-8 flex flex-col">
                  <header className="flex justify-between items-end border-b border-[#262626] pb-4 mb-6">
                    <div>
                      <h2 className="font-label-caps text-label-caps text-white uppercase">USER REGISTRY</h2>
                      <p className="font-metadata text-metadata text-[#8e9192] mt-1">ACTIVE DIRECTORY V.2.1</p>
                    </div>
                    <span className="font-metadata text-metadata text-[#8e9192] border border-[#262626] px-2 py-1 bg-[#111111]">
                      TOTAL: {userRegistry.length}
                    </span>
                  </header>
                  <div className="flex-1 overflow-x-auto">
                    <table className="w-full text-left border-collapse font-metadata text-metadata">
                      <thead>
                        <tr className="text-[#8e9192] border-b border-[#262626] font-label-caps text-label-caps">
                          <th className="py-3 pr-4 font-normal">USER ID</th>
                          <th className="py-3 px-4 font-normal">ROLE</th>
                          <th className="py-3 px-4 font-normal">STATUS</th>
                          <th className="py-3 px-4 font-normal text-right">LAST ACTIVE</th>
                        </tr>
                      </thead>
                      <tbody>
                        {userRegistry.map((u) => (
                          <tr key={u.id} className="border-b border-[#262626] hover:bg-[#111111] transition-colors">
                            <td className="py-3 pr-4 text-white font-bold">{u.userId}</td>
                            <td className={`py-3 px-4 ${u.role === 'REVIEWER' ? 'text-[#F0C808]' : 'text-[#c6c6c6]'}`}>
                              {u.role}
                            </td>
                            <td className="py-3 px-4">
                              <span
                                className={`px-2 py-0.5 border text-[10px] ${
                                  u.status === 'ACTIVE'
                                    ? 'bg-[#111111] border-[#262626] text-white'
                                    : 'bg-[#181818] border-[#262626] text-[#8e9192]'
                                }`}
                              >
                                {u.status}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-right text-[#8e9192]">{u.lastActive}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>

                {/* ROLE DEFINITIONS (4 cols) */}
                <section className="col-span-12 lg:col-span-4 bg-[#080808] p-8 flex flex-col">
                  <header className="flex justify-between items-end border-b border-[#262626] pb-4 mb-6">
                    <h2 className="font-label-caps text-label-caps text-white uppercase">ROLE: REVIEWER</h2>
                    <span className="font-metadata text-metadata text-[#8e9192] border border-[#262626] px-2 py-1 bg-[#111111]">
                      ID: ROL-992
                    </span>
                  </header>
                  <div className="flex-1 overflow-y-auto pr-2 font-label-caps text-[11px]">
                    <ul className="flex flex-col divide-y divide-[#262626]">
                      <li className="py-2.5 flex justify-between items-center text-white">
                        <span>VIEW CASES</span>
                        <span className="material-symbols-outlined text-[#F0C808] text-sm">check</span>
                      </li>
                      <li className="py-2.5 flex justify-between items-center text-[#8e9192]">
                        <span>CREATE CASES</span>
                        <span className="material-symbols-outlined text-sm">close</span>
                      </li>
                      <li className="py-2.5 flex justify-between items-center text-white">
                        <span>VIEW EVIDENCE</span>
                        <span className="material-symbols-outlined text-[#F0C808] text-sm">check</span>
                      </li>
                      <li className="py-2.5 flex justify-between items-center text-[#8e9192]">
                        <span>EDIT EVIDENCE</span>
                        <span className="material-symbols-outlined text-sm">close</span>
                      </li>
                      <li className="py-2.5 flex justify-between items-center text-white">
                        <span>EXPORT REPORTS</span>
                        <span className="material-symbols-outlined text-[#F0C808] text-sm">check</span>
                      </li>
                      <li className="py-2.5 flex justify-between items-center text-[#8e9192] opacity-70">
                        <span>EXECUTE MANUAL OVERRIDE</span>
                        <span className="material-symbols-outlined text-sm">close</span>
                      </li>
                      <li className="py-2.5 flex justify-between items-center text-[#8e9192]">
                        <span>MANAGE DATA SOURCES</span>
                        <span className="material-symbols-outlined text-sm">close</span>
                      </li>
                      <li className="py-2.5 flex justify-between items-center text-[#8e9192]">
                        <span>MANAGE MODELS</span>
                        <span className="material-symbols-outlined text-sm">close</span>
                      </li>
                    </ul>
                  </div>
                </section>

                {/* AUTHORIZATION LOGIC & AUDIT (12 cols) */}
                <section className="col-span-12 bg-[#080808] p-8 flex flex-col">
                  <header className="flex justify-between items-end border-b border-[#262626] pb-4 mb-6">
                    <div>
                      <h2 className="font-label-caps text-label-caps text-white uppercase">AUTHORIZATION AUDIT LOG</h2>
                      <p className="font-metadata text-metadata text-[#8e9192] mt-1">
                        LATEST TARGET: EXECUTE_MANUAL_OVERRIDE
                      </p>
                    </div>
                    <span className="font-metadata text-metadata text-[#F0C808] font-bold">LIVE FEED</span>
                  </header>
                  <div className="flex flex-col md:flex-row gap-6">
                    {/* Scenario A (AUTHORIZED) */}
                    <div className="flex-1 border border-[#262626] p-6 bg-[#111111]">
                      <div className="flex justify-between items-center mb-4">
                        <span className="font-metadata px-2 py-1 border border-white text-white">SCENARIO A</span>
                        <span className="font-metadata text-metadata text-[#8e9192]">T-MINUS 12m</span>
                      </div>
                      <div className="font-metadata text-metadata flex flex-col gap-2">
                        <div className="flex justify-between border-b border-[#262626] pb-2">
                          <span className="text-[#8e9192]">SUBJECT:</span>
                          <span className="text-white font-bold">ANALYST_01 (INVESTIGATOR)</span>
                        </div>
                        <div className="flex justify-between border-b border-[#262626] pb-2">
                          <span className="text-[#8e9192]">ACTION:</span>
                          <span className="text-white font-mono">EXECUTE_MANUAL_OVERRIDE</span>
                        </div>
                        <div className="flex justify-between pt-2">
                          <span className="text-[#8e9192]">RESULT:</span>
                          <span className="text-[#F0C808] font-bold flex items-center gap-1">
                            <span className="material-symbols-outlined text-sm">verified_user</span> AUTHORIZED
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Scenario B (DENIED) */}
                    <div className="flex-1 border border-[#262626] p-6 bg-[#080808] opacity-80">
                      <div className="flex justify-between items-center mb-4">
                        <span className="font-metadata px-2 py-1 border border-[#262626] text-[#8e9192]">SCENARIO B</span>
                        <span className="font-metadata text-metadata text-[#8e9192]">T-MINUS 45m</span>
                      </div>
                      <div className="font-metadata text-metadata flex flex-col gap-2">
                        <div className="flex justify-between border-b border-[#262626] pb-2">
                          <span className="text-[#8e9192]">SUBJECT:</span>
                          <span className="text-white font-bold">REVIEWER_03 (REVIEWER)</span>
                        </div>
                        <div className="flex justify-between border-b border-[#262626] pb-2">
                          <span className="text-[#8e9192]">ACTION:</span>
                          <span className="text-white font-mono">EXECUTE_MANUAL_OVERRIDE</span>
                        </div>
                        <div className="flex justify-between pt-2">
                          <span className="text-[#8e9192]">RESULT:</span>
                          <span className="text-[#8e9192] flex items-center gap-1">
                            <span className="material-symbols-outlined text-sm">block</span> INSUFFICIENT PRIVILEGES
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </section>
              </div>
            </div>
          )}

          {/* TAB 3: ACTIVE SESSIONS */}
          {activeTab === 'SESSIONS' && (
            <div className="space-y-6 animate-fade-in">
              <div>
                <h1 className="font-headline-lg text-headline-lg text-white uppercase">ACTIVE SESSIONS</h1>
                <p className="font-metadata text-metadata text-[#8e9192] mt-2 max-w-xl">
                  Manage active connections, terminals, and field agent authentications with immediate revocation capabilities.
                </p>
              </div>

              {/* KPI Metrics */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-gutter bg-[#262626] border border-[#262626]">
                <div className="bg-[#080808] p-6 flex flex-col gap-1">
                  <span className="font-metadata text-metadata text-[#8e9192] uppercase">ACTIVE SESSIONS</span>
                  <span className="font-headline-lg text-headline-lg text-white font-bold">{sessions.length}</span>
                </div>
                <div className="bg-[#080808] p-6 flex flex-col gap-1">
                  <span className="font-metadata text-metadata text-[#8e9192] uppercase">CONCURRENT PEAK</span>
                  <span className="font-headline-lg text-headline-lg text-white font-bold">5</span>
                </div>
                <div className="bg-[#080808] p-6 flex flex-col gap-1">
                  <span className="font-metadata text-metadata text-[#8e9192] uppercase">SECURITY SCORE</span>
                  <span className="font-headline-lg text-headline-lg text-[#F0C808] font-bold">98/100</span>
                </div>
                <div className="bg-[#080808] p-6 flex flex-col gap-1">
                  <span className="font-metadata text-metadata text-[#8e9192] uppercase">MFA ENFORCED</span>
                  <span className="font-headline-lg text-headline-lg text-white font-bold">100%</span>
                </div>
              </div>

              {/* Sessions Table */}
              <div className="bg-[#080808] border border-[#262626] p-8">
                <div className="flex justify-between items-center border-b border-[#262626] pb-4 mb-6">
                  <h3 className="font-label-caps text-label-caps text-white uppercase">SESSION REGISTRY</h3>
                  <span className="font-metadata text-metadata text-[#8e9192]">REVOCATION: IMMEDIATE</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse font-metadata text-metadata">
                    <thead>
                      <tr className="text-[#8e9192] border-b border-[#262626] font-label-caps text-label-caps">
                        <th className="py-3 pr-4 font-normal">SESSION ID</th>
                        <th className="py-3 px-4 font-normal">IP ADDRESS</th>
                        <th className="py-3 px-4 font-normal">DEVICE / AGENT</th>
                        <th className="py-3 px-4 font-normal">LOCATION</th>
                        <th className="py-3 px-4 font-normal">LAST ACTIVE</th>
                        <th className="py-3 pl-4 font-normal text-right">ACTION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sessions.map((s) => (
                        <tr key={s.id} className="border-b border-[#262626] hover:bg-[#111111] transition-colors">
                          <td className="py-3 pr-4 text-white font-mono font-bold flex items-center gap-2">
                            {s.sessionId}
                            {s.isCurrent && (
                              <span className="text-[9px] bg-[#111111] text-[#F0C808] border border-[#F0C808] px-1">
                                CURRENT
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-[#c6c6c6]">{s.ipAddress}</td>
                          <td className="py-3 px-4 text-white">{s.device}</td>
                          <td className="py-3 px-4 text-[#8e9192]">{s.location}</td>
                          <td className="py-3 px-4 text-white">{s.lastActive}</td>
                          <td className="py-3 pl-4 text-right">
                            {s.isCurrent ? (
                              <span className="text-[#8e9192] text-[10px]">CURRENT</span>
                            ) : (
                              <button
                                onClick={() => handleRevoke(s.sessionId)}
                                className="border border-[#353535] text-[#ffb4ab] hover:border-[#ffb4ab] hover:bg-[#1a0505] px-2 py-1 text-[10px] font-label-caps uppercase transition-colors cursor-pointer"
                              >
                                REVOKE
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4 & 5: NOTIFICATIONS & DEFAULTS */}
          {(activeTab === 'NOTIFICATIONS' || activeTab === 'DEFAULTS') && (
            <div className="space-y-6 animate-fade-in">
              <div>
                <h1 className="font-headline-lg text-headline-lg text-white uppercase">{activeTab}</h1>
                <p className="font-metadata text-metadata text-[#8e9192] mt-2 max-w-xl">
                  Adjust global workspace preferences, ingestion thresholds, and notification delivery policies.
                </p>
              </div>
              <div className="bg-[#080808] border border-[#262626] p-8 space-y-4">
                <div className="flex justify-between items-center py-3 border-b border-[#262626]">
                  <div>
                    <div className="font-label-caps text-label-caps text-white">HIGH LUMINANCE ALERT POPUPS</div>
                    <div className="font-metadata text-metadata text-[#8e9192]">Show golden banner for P1 anomalies</div>
                  </div>
                  <span className="text-[#F0C808] font-label-caps text-label-caps font-bold">ENABLED</span>
                </div>
                <div className="flex justify-between items-center py-3 border-b border-[#262626]">
                  <div>
                    <div className="font-label-caps text-label-caps text-white">AUTO EVIDENCE NORMALIZATION</div>
                    <div className="font-metadata text-metadata text-[#8e9192]">Run NLP pipeline on ingestion</div>
                  </div>
                  <span className="text-[#F0C808] font-label-caps text-label-caps font-bold">ENABLED</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};
