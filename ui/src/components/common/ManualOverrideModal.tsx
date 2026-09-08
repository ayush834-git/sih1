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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-xs p-4">
      <div className="w-full max-w-lg bg-[#080808] border-2 border-[#F0C808] shadow-[0_0_50px_rgba(240,200,8,0.2)] flex flex-col p-8">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-[#262626] pb-4 mb-6">
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
            className="text-[#8e9192] hover:text-white font-metadata text-xs cursor-pointer"
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
          <div className="bg-[#111111] p-3 border border-[#262626] font-metadata text-[11px] space-y-1">
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
              className="w-full bg-[#111111] border border-[#353535] p-3 font-metadata text-metadata text-white placeholder:text-[#8e9192] focus:border-[#F0C808] focus:outline-none resize-none"
              required
            />
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-3 pt-4 border-t border-[#262626]">
          <button
            type="button"
            onClick={() => setManualOverrideModalOpen(false)}
            className="px-4 py-2 border border-[#262626] font-label-caps text-label-caps text-[#c6c6c6] hover:text-white hover:border-white transition-colors cursor-pointer"
          >
            ABORT
          </button>
          <button
            type="button"
            disabled={!justification.trim() || isSubmitting}
            onClick={handleSubmit}
            className="px-6 py-2 bg-[#F0C808] text-[#000001] font-label-caps text-label-caps font-bold hover:bg-white transition-colors disabled:opacity-50 cursor-pointer flex items-center gap-2"
          >
            {isSubmitting ? 'ENFORCING...' : 'CONFIRM MANUAL OVERRIDE'}
          </button>
        </div>
      </div>
    </div>
  );
};
