import React, { useState } from 'react';
import { GlassPanel } from './GlassPanel';

/**
 * CodeFronts GLZ-16 — Progressive Disclosure Glass Card Technique
 *
 * Source: CodeFronts GLZ-16
 * Principle:
 * PRIMARY INFORMATION (immediately visible)
 *   ↓
 * SUPPORTING INFORMATION (secondary / contextual)
 *   ↓
 * TECHNICAL DETAILS (deep evidence / diagnostics behind deliberate disclosure)
 *
 * Solves "information overload" by keeping secondary technical diagnostics
 * (R², AR coefficients, 15D tensor, blast radius internals, session manifests)
 * neatly accessible without crowding the default viewport.
 */

export interface GlassProgressiveDisclosureProps {
  /**
   * Monospace trigger label, e.g. "INSPECT FULL 15-DIMENSIONAL STATE TENSOR"
   */
  title: string;
  /**
   * Optional summary badge or metadata displayed alongside the trigger
   */
  badge?: string;
  /**
   * Initial disclosure state (defaults to false)
   */
  defaultOpen?: boolean;
  /**
   * Optional custom class for outer container
   */
  className?: string;
  /**
   * Technical details rendered inside the progressive glass drawer
   */
  children: React.ReactNode;
}

export const GlassProgressiveDisclosure: React.FC<GlassProgressiveDisclosureProps> = ({
  title,
  badge,
  defaultOpen = false,
  className = '',
  children,
}) => {
  const [isOpen, setIsOpen] = useState<boolean>(defaultOpen);

  return (
    <section className={`font-mono ${className}`.trim()}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        className="w-full group flex items-center justify-between px-4 py-3 rounded-2xl bg-[#080808]/80 hover:bg-[#121216] border border-[#27272A]/60 hover:border-[#F0C808]/40 transition-all text-left focus:outline-none focus-visible:ring-1 focus-visible:ring-[#F0C808] cursor-pointer select-none"
      >
        <div className="flex items-center gap-3">
          <span className="text-[#F0C808] font-bold text-sm tracking-tighter">
            {isOpen ? '[−]' : '[+]'}
          </span>
          <span className="text-xs uppercase tracking-wider text-[#A1A1AA] group-hover:text-white transition-colors font-medium">
            {title}
          </span>
        </div>
        {badge && (
          <span className="text-[10px] text-[#71717A] group-hover:text-[#A1A1AA] uppercase tracking-widest px-2.5 py-0.5 rounded-full bg-white/[0.04] border border-white/[0.06]">
            {badge}
          </span>
        )}
      </button>

      {isOpen && (
        <GlassPanel
          variant="subtle"
          rounded="rounded-2xl"
          className="mt-2.5 p-6 border border-[#27272A]/60 space-y-4 animate-fade-in"
        >
          {children}
        </GlassPanel>
      )}
    </section>
  );
};
