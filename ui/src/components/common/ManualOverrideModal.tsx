import React, { useState } from 'react';
import { useControlCenterStore } from '../../store/useControlCenterStore';

export const ManualOverrideModal: React.FC = () => {
  const { isManualOverrideModalOpen, setManualOverrideModalOpen, triggerManualOverride, currentUser } =
    useControlCenterStore();
  const [justification, setJustification] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isManualOverrideModalOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!justification.trim()) return;
    setIsSubmitting(true);
    setTimeout(() => {
      triggerManualOverride(justification);
      setIsSubmitting(false);
      setJustification('');
    }, 600);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md p-4">
      <div className="w-full max-w-lg bg-[#080808] border-2 border-[#F0C808]/70 shadow-[0_0_50px_rgba(240,200,8,0.2)] flex flex-col p-8 rounded-3xl overflow-hidden">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-[#27272A]/70 pb-4 mb-6">
          <div className="flex items-center gap-3">
            <span className="material-symbols-outlined text-[#F0C808] text-[28px]">warning</span>
            <div>
              <h2 className="font-label-caps text-label-caps text-[#F0C808] uppercase tracking-widest">
                CRITICAL INTERVENTION // MANUAL OVERRIDE
              </h2>
              <span className="font-metadata text-metadata text-[#c6c6c6]">SYS_OVERRIDE_AUTH_GATEWAY</span>
            </div>
          </div>
          <button
            onClick={() => setManualOverrideModalOpen(false)}
            className="w-7 h-7 rounded-full flex items-center justify-center text-[#8e9192] hover:text-white hover:bg-white/10 font-metadata text-xs cursor-pointer transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Warning Body */}
        <div className="space-y-4 font-body-rg text-[13px] text-[#c6c6c6] mb-6">
          <p className="border-l-2 border-[#F0C808] pl-3 text-white">
            Initiating a manual override will suspend all autonomous algorithmic containment rules, bypass automated
            drift gates, and transition the Control Centre to <strong>RECOVERY</strong> state.
          </p>
          <div className="bg-[#111111] p-4 border border-[#27272A]/70 font-metadata text-[11px] space-y-1 rounded-2xl">
            <div className="flex justify-between">
              <span className="text-[#8e9192]">OPERATOR:</span>
              <span className="text-white">{currentUser.name} ({currentUser.clearance})</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#8e9192]">TIMESTAMP:</span>
              <span className="text-white">{new Date().toISOString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#8e9192]">TARGET PLANE:</span>
              <span className="text-[#F0C808]">CORE_CONTROL_ORCHESTRATOR</span>
            </div>
          </div>

          <div>
            <label className="block font-label-caps text-label-caps text-white mb-2 uppercase">
              Operational Justification (Mandatory for Audit Trail):
            </label>
            <textarea
              rows={3}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder="State reason for manual threshold override and subsequent recovery vector..."
              className="w-full bg-[#111111] border border-[#353535] p-3.5 font-metadata text-metadata text-white placeholder:text-[#8e9192] focus:border-[#F0C808] focus:outline-none resize-none rounded-2xl"
              required
            />
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-3 pt-4 border-t border-[#27272A]/70">
          <button
            type="button"
            onClick={() => setManualOverrideModalOpen(false)}
            className="px-5 py-2.5 border border-[#262626] font-label-caps text-label-caps text-[#c6c6c6] hover:text-white hover:border-white transition-colors cursor-pointer rounded-full"
          >
            ABORT
          </button>
          <button
            type="button"
            data-cursor="critical"
            disabled={!justification.trim() || isSubmitting}
            onClick={handleSubmit}
            className="px-6 py-2.5 bg-[#F0C808] text-[#000001] font-label-caps text-label-caps font-bold hover:bg-[#FFE14C] transition-colors disabled:opacity-50 cursor-pointer flex items-center gap-2 rounded-full shadow-[0_0_15px_rgba(240,200,8,0.3)]"
          >
            {isSubmitting ? 'ENFORCING...' : 'CONFIRM MANUAL OVERRIDE'}
          </button>
        </div>
      </div>
    </div>
  );
};
