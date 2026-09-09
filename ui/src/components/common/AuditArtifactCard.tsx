import React from 'react';
import { GlassPanel } from './GlassPanel';
import type { ResponseExecutionResponse } from '../../types/runtime';

/**
 * CodeFronts GLZ-19 — Event Ticket / Artifact Geometry
 *
 * Source: CodeFronts GLZ-19
 * Adaptations for SIH Predictive Defense:
 * - Applied strictly to AUDIT & TRACE artifacts (execution records, provenance ledger).
 * - Perforated notched ticket divider separating high-level execution action from immutable verification signatures.
 * - Deterministic visual barcode derived mathematically from the real execution_id hash.
 * - Zero fake QR codes or synthetic IDs.
 */

export interface AuditArtifactCardProps {
  record: ResponseExecutionResponse;
  className?: string;
}

/**
 * Deterministic barcode SVG generator based on character codes of the real identifier.
 */
function RealIdBarcode({ id }: { id: string }) {
  const chars = (id || 'AUDIT-ID').slice(0, 32).split('');
  return (
    <svg
      className="h-8 w-44 opacity-60"
      viewBox="0 0 160 32"
      fill="currentColor"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      {chars.map((char, i) => {
        const code = char.charCodeAt(0);
        const width = (code % 3) + 1;
        const x = i * 5;
        return <rect key={i} x={x} y="0" width={width} height="32" fill="#A1A1AA" />;
      })}
    </svg>
  );
}

export const AuditArtifactCard: React.FC<AuditArtifactCardProps> = ({ record, className = '' }) => {
  const isVerifiedSuccess = record.status === 'VERIFIED_SUCCESS';
  const isFailed = record.status === 'FAILED';

  return (
    <GlassPanel
      variant="default"
      rounded="rounded-3xl"
      className={`p-6 border border-[#27272A]/70 relative overflow-hidden ${className}`.trim()}
    >
      {/* Top Header: Execution Action & Status */}
      <div className="flex flex-wrap items-start justify-between gap-4 font-mono">
        <div>
          <div className="text-[10px] text-[#71717A] uppercase tracking-widest mb-1 flex items-center gap-2">
            <span>DISPATCH ARTIFACT</span>
            <span className="text-[#27272A]">//</span>
            <span className="text-[#A1A1AA]">STAGE 04 → 06</span>
          </div>
          <h3 className="text-xl font-bold text-white tracking-tight uppercase">
            {record.action_id}
          </h3>
          <div className="text-xs text-[#A1A1AA] mt-0.5">
            Target: <span className="text-white font-semibold">{String(record.applied_parameters?.target_node_id || record.applied_parameters?.target || 'GATEWAY_NODE')}</span>
          </div>
        </div>

        <div className="flex flex-col items-end gap-1.5">
          <span
            className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-widest border ${
              isVerifiedSuccess
                ? 'bg-green-500/10 text-green-400 border-green-500/30'
                : isFailed
                ? 'bg-red-500/10 text-red-400 border-red-500/30'
                : 'bg-[#F0C808]/10 text-[#F0C808] border-[#F0C808]/30'
            }`}
          >
            {record.status}
          </span>
          <span className="text-[10px] text-[#71717A]">
            {record.is_verified ? '✓ VERIFIED CLOSED-LOOP' : 'AWAITING TELEMETRY'}
          </span>
        </div>
      </div>

      {/* Perforated Notched Ticket Divider (GLZ-19) */}
      <div className="glz-ticket-divider my-4" />

      {/* Bottom Segment: Cryptographic Provenance & Barcode */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono text-xs pt-1">
        <div className="space-y-1.5">
          <div>
            <span className="text-[10px] text-[#71717A] uppercase tracking-wider block">EXECUTION HASH / ID</span>
            <span className="text-xs text-[#A1A1AA] select-all font-semibold">
              {record.execution_id}
            </span>
          </div>
          {record.message && (
            <div className="text-[11px] text-[#71717A] max-w-md truncate">
              {record.message}
            </div>
          )}
        </div>

        <div className="flex flex-col items-start sm:items-end gap-1 shrink-0">
          <RealIdBarcode id={record.execution_id} />
          <span className="text-[9px] text-[#52525B] tracking-widest uppercase">
            IMMUTABLE LEDGER RECORD
          </span>
        </div>
      </div>
    </GlassPanel>
  );
};
