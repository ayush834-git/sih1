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
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs animate-fade-in">
      <div
        className="w-full max-w-[480px] h-full bg-[#080808] border-l border-[#262626] flex flex-col shadow-2xl z-50 text-white"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="p-6 border-b border-[#262626] bg-[#0A0A0A] flex justify-between items-center">
          <div>
            <h2 className="font-label-caps text-label-caps uppercase text-white tracking-widest flex items-center gap-2">
              <span className="w-1.5 h-1.5 bg-[#F0C808] inline-block"></span>
              ACTION_REQUIRED
            </h2>
            <p className="font-metadata text-metadata text-[#8e9192] mt-1">
              {unreadCount} UNREAD ALERTS
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={markAllNotificationsRead}
              className="px-2 py-1 border border-[#262626] text-[10px] uppercase font-metadata text-[#8e9192] hover:text-white hover:border-white transition-colors cursor-pointer"
            >
              MARK_ALL_READ
            </button>
            <button
              onClick={() => setNotificationDrawerOpen(false)}
              className="p-1 border border-transparent hover:border-[#262626] text-[#8e9192] hover:text-white transition-colors cursor-pointer"
            >
              <span className="material-symbols-outlined text-[18px]">close</span>
            </button>
          </div>
        </div>

        {/* Categories Toggle Strip */}
        <div className="flex border-b border-[#262626] bg-[#111111] overflow-x-auto no-scrollbar font-label-caps text-[10px]">
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
                className={`px-4 py-3 border-b-2 whitespace-nowrap transition-colors cursor-pointer ${
                  isActive
                    ? 'border-white text-white bg-[#181818] font-bold'
                    : 'border-transparent text-[#8e9192] hover:text-white hover:bg-[#151515]'
                }`}
              >
                {cat} ({count})
              </button>
            );
          })}
        </div>

        {/* Notification List */}
        <div className="flex-1 overflow-y-auto divide-y divide-[#262626]">
          {filteredNotifications.map((notif) => {
            if (notif.isUnread) {
              return (
                <div
                  key={notif.id}
                  className="p-6 bg-[#0C0C0C] hover:bg-[#111111] transition-colors relative cursor-pointer group"
                >
                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-[#F0C808]"></div>
                  <div className="flex justify-between items-start mb-3">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 uppercase text-[9px] tracking-wider border ${
                          notif.isError
                            ? 'text-[#ffb4ab] border-[#93000a] bg-[#1a0505]'
                            : 'text-white border-[#353535] bg-[#111111]'
                        }`}
                      >
                        {notif.chip}
                      </span>
                      <span className="font-metadata text-metadata text-[#8e9192]">
                        {notif.timeOffset}
                      </span>
                    </div>
                    <span className="font-metadata text-metadata text-[#8e9192] uppercase">
                      ID: {notif.id}
                    </span>
                  </div>
                  <p className="font-body-rg text-[14px] text-white mb-4 leading-relaxed">
                    {notif.description}
                  </p>
                  {notif.actionText && (
                    <div className="flex justify-between items-center mt-2 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        onClick={() => handleAction(notif)}
                        className="bg-white text-black text-[10px] py-1 px-3 font-metadata uppercase font-bold hover:bg-[#c6c6c6] transition-colors cursor-pointer"
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
                className="p-6 bg-[#080808] hover:bg-[#0C0C0C] transition-colors relative cursor-pointer opacity-60 hover:opacity-100"
              >
                <div className="flex justify-between items-start mb-3">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 uppercase text-[9px] tracking-wider border border-[#262626] bg-[#111111] text-[#8e9192]">
                      {notif.chip}
                    </span>
                    <span className="font-metadata text-metadata text-[#8e9192]">
                      {notif.timeOffset}
                    </span>
                  </div>
                  <span className="font-metadata text-metadata text-[#8e9192] uppercase">
                    ID: {notif.id}
                  </span>
                </div>
                <p className="font-body-rg text-[14px] text-[#c6c6c6] mb-2 leading-relaxed">
                  {notif.description}
                </p>
              </div>
            );
          })}
        </div>

        {/* Preferences Footer */}
        <div className="p-4 border-t border-[#262626] bg-[#0A0A0A] flex justify-between items-center">
          <span className="font-label-caps text-label-caps text-[#8e9192] uppercase">
            NOTIF_PREF: VERBOSE
          </span>
          <button
            onClick={() => {
              navigate('/command-center/settings');
              setNotificationDrawerOpen(false);
            }}
            className="px-2 py-1 border border-transparent hover:border-[#262626] text-[10px] font-metadata uppercase text-white flex items-center gap-1 cursor-pointer"
          >
            <span className="material-symbols-outlined text-[14px]">tune</span> CONFIGURE
          </button>
        </div>
      </div>
    </div>
  );
};
