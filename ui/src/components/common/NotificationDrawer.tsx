import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useControlCenterStore } from '../../store/useControlCenterStore';

export const NotificationDrawer: React.FC = () => {
  const {
    isNotificationDrawerOpen,
    setNotificationDrawerOpen,
    notifications,
    markAllNotificationsRead,
    setActiveCaseId,
    setSelectedEvidenceId,
  } = useControlCenterStore();

  const [activeCategory, setActiveCategory] = useState<string>('ALL');
  const navigate = useNavigate();

  if (!isNotificationDrawerOpen) return null;

  const filteredNotifications =
    activeCategory === 'ALL'
      ? notifications
      : notifications.filter((n) => n.category === activeCategory);

  const handleAction = (notif: typeof notifications[0]) => {
    if (notif.caseId) {
      setActiveCaseId(notif.caseId);
    }
    if (notif.evidenceId) {
      setSelectedEvidenceId(notif.evidenceId);
    }
    if (notif.actionRoute) {
      navigate(notif.actionRoute);
    }
    setNotificationDrawerOpen(false);
  };

  const unreadCount = notifications.filter((n) => n.isUnread).length;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm animate-fade-in">
      <div
        className="w-full max-w-[480px] h-full bg-[#080808] border-l border-[#27272A]/80 rounded-l-3xl flex flex-col shadow-2xl z-50 text-white overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="p-6 border-b border-[#27272A]/60 bg-[#0A0A0A] flex justify-between items-center">
          <div>
            <h2 className="font-label-caps text-label-caps uppercase text-white tracking-widest flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-[#F0C808] shadow-[0_0_8px_rgba(240,200,8,0.6)] animate-pulse"></span>
              ACTION_REQUIRED
            </h2>
            <p className="font-metadata text-metadata text-[#8e9192] mt-1">
              {unreadCount} UNREAD ALERTS
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={markAllNotificationsRead}
              className="px-3 py-1 border border-[#27272A] text-[10px] uppercase font-metadata text-[#8e9192] hover:text-white hover:border-white transition-colors cursor-pointer rounded-full"
            >
              MARK_ALL_READ
            </button>
            <button
              onClick={() => setNotificationDrawerOpen(false)}
              className="w-8 h-8 rounded-full flex items-center justify-center border border-transparent hover:border-[#27272A] hover:bg-white/10 text-[#8e9192] hover:text-white transition-colors cursor-pointer"
            >
              <span className="material-symbols-outlined text-[18px]">close</span>
            </button>
          </div>
        </div>

        {/* Categories Toggle Strip (Pill Bar) */}
        <div className="flex gap-1.5 p-2.5 border-b border-[#27272A]/50 bg-[#111111] overflow-x-auto no-scrollbar font-label-caps text-[10px]">
          {(['ALL', 'ALERT', 'CASE', 'EVIDENCE', 'REVIEW', 'SYSTEM'] as const).map((cat) => {
            const count =
              cat === 'ALL'
                ? notifications.length
                : notifications.filter((n) => n.category === cat).length;
            const isActive = activeCategory === cat;
            return (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-3 py-1.5 rounded-full whitespace-nowrap transition-all cursor-pointer ${
                  isActive
                    ? 'bg-[#F0C808] text-black font-bold shadow-[0_0_10px_rgba(240,200,8,0.25)]'
                    : 'text-[#8e9192] hover:text-white hover:bg-white/[0.06]'
                }`}
              >
                {cat} ({count})
              </button>
            );
          })}
        </div>

        {/* Notification List */}
        <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
          {filteredNotifications.map((notif) => {
            if (notif.isUnread) {
              return (
                <div
                  key={notif.id}
                  className="p-5 bg-[#0C0C0C] hover:bg-[#141414] border border-[#27272A]/60 rounded-2xl transition-all relative cursor-pointer group shadow-[0_2px_12px_rgba(0,0,0,0.3)]"
                >
                  <div className="absolute left-0 top-3 bottom-3 w-1 bg-[#F0C808] rounded-r-full"></div>
                  <div className="flex justify-between items-start mb-2.5 pl-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2.5 py-0.5 uppercase text-[9px] tracking-wider rounded-full border ${
                          notif.isError
                            ? 'text-[#ffb4ab] border-[#93000a] bg-[#1a0505]'
                            : 'text-[#F0C808] border-[#F0C808]/40 bg-[#F0C808]/10'
                        }`}
                      >
                        {notif.chip}
                      </span>
                      <span className="font-metadata text-metadata text-[#8e9192]">
                        {notif.timeOffset}
                      </span>
                    </div>
                    <span className="font-metadata text-metadata text-[#8e9192] uppercase text-[10px]">
                      ID: {notif.id}
                    </span>
                  </div>
                  <p className="font-body-rg text-[13px] text-white mb-3 pl-2 leading-relaxed">
                    {notif.description}
                  </p>
                  {notif.actionText && (
                    <div className="flex justify-between items-center pl-2 pt-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        onClick={() => handleAction(notif)}
                        className="bg-[#F0C808] text-black text-[10px] py-1 px-3.5 font-metadata uppercase font-bold hover:bg-white rounded-full transition-colors cursor-pointer shadow-[0_0_10px_rgba(240,200,8,0.25)]"
                      >
                        {notif.actionText}
                      </button>
                      <span className="material-symbols-outlined text-[#8e9192] text-[16px]">
                        arrow_forward
                      </span>
                    </div>
                  )}
                </div>
              );
            }

            return (
              <div
                key={notif.id}
                className="p-5 bg-[#080808] hover:bg-[#0C0C0C] border border-[#27272A]/30 rounded-2xl transition-colors relative cursor-pointer opacity-60 hover:opacity-100"
              >
                <div className="flex justify-between items-start mb-2.5">
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-0.5 uppercase text-[9px] tracking-wider border border-[#262626] bg-[#111111] text-[#8e9192] rounded-full">
                      {notif.chip}
                    </span>
                    <span className="font-metadata text-metadata text-[#8e9192]">
                      {notif.timeOffset}
                    </span>
                  </div>
                  <span className="font-metadata text-metadata text-[#8e9192] uppercase text-[10px]">
                    ID: {notif.id}
                  </span>
                </div>
                <p className="font-body-rg text-[13px] text-[#c6c6c6] leading-relaxed">
                  {notif.description}
                </p>
              </div>
            );
          })}
        </div>

        {/* Preferences Footer */}
        <div className="p-4 border-t border-[#27272A]/60 bg-[#0A0A0A] flex justify-between items-center">
          <span className="font-label-caps text-label-caps text-[#8e9192] uppercase text-[10px]">
            NOTIF_PREF: VERBOSE
          </span>
          <button
            onClick={() => {
              navigate('/command-center/settings');
              setNotificationDrawerOpen(false);
            }}
            className="px-3 py-1 border border-transparent hover:border-[#27272A] rounded-full text-[10px] font-metadata uppercase text-white flex items-center gap-1.5 cursor-pointer transition-colors"
          >
            <span className="material-symbols-outlined text-[14px]">tune</span> CONFIGURE
          </button>
        </div>
      </div>
    </div>
  );
};
