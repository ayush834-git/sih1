import React from 'react';

export interface SkeletonBaseProps extends React.HTMLAttributes<HTMLDivElement> {
  width?: string | number;
  height?: string | number;
  rounded?: 'none' | 'sm' | 'md' | 'lg' | 'xl' | '2xl' | '3xl' | 'full';
  accent?: boolean;
  delayIndex?: 1 | 2 | 3 | 4 | 5;
  className?: string;
}

const ROUNDED_MAP: Record<string, string> = {
  none: 'rounded-none',
  sm: 'rounded-sm',
  md: 'rounded-md',
  lg: 'rounded-lg',
  xl: 'rounded-xl',
  '2xl': 'rounded-2xl',
  '3xl': 'rounded-3xl',
  full: 'rounded-full',
};

/**
 * ── Foundational Shimmer Primitive: SkeletonBase ─────────────────────────────
 * Provides 1.8s translateX shimmer mechanism, dark smoky grey surface, and
 * prefers-reduced-motion accessibility compliance.
 */
export const SkeletonBase: React.FC<SkeletonBaseProps> = ({
  width,
  height,
  rounded = 'md',
  accent = false,
  delayIndex,
  className = '',
  style,
  ...rest
}) => {
  const roundedClass = ROUNDED_MAP[rounded] || 'rounded-md';
  const shimmerClass = accent ? 'ssc-shimmer-accent' : 'ssc-shimmer-base';
  const delayClass = delayIndex ? `ssc-delay-${delayIndex}` : '';

  return (
    <div
      className={`${shimmerClass} ${roundedClass} ${delayClass} ${className}`}
      style={{
        width: typeof width === 'number' ? `${width}px` : width,
        height: typeof height === 'number' ? `${height}px` : height,
        ...style,
      }}
      aria-hidden="true"
      {...rest}
    />
  );
};

/* =============================================================================
   1. CODEFRONTS SSC-07 — SEARCH RESULT / TRACE LIST ITEM
   Anatomy:
   - Source / Status badge marker + timestamp metadata line
   - Asymmetric larger spacing between title and supporting details
   - Event / Trace title line
   - Supporting evidence lines
   ============================================================================= */

export interface SearchTraceSkeletonProps {
  count?: number;
  className?: string;
  ariaLabel?: string;
}

export const SearchTraceSkeleton: React.FC<SearchTraceSkeletonProps> = ({
  count = 3,
  className = '',
  ariaLabel = 'Loading trace evidence records...',
}) => {
  const items = Array.from({ length: count }, (_, i) => i);

  return (
    <div
      role="status"
      aria-busy="true"
      aria-label={ariaLabel}
      className={`space-y-3.5 font-mono ${className}`}
    >
      <span className="sr-only">{ariaLabel}</span>
      {items.map((idx) => {
        const delay = ((idx % 5) + 1) as 1 | 2 | 3 | 4 | 5;
        return (
          <div
            key={idx}
            className="ssc-trace-card border border-white/5 bg-[#08080A] rounded-2xl p-5"
          >
            {/* Metadata Line */}
            <div className="flex items-center gap-2.5 mb-2.5">
              <SkeletonBase
                width={8}
                height={8}
                rounded="full"
                accent={idx === 0}
                delayIndex={delay}
              />
              <SkeletonBase
                width="110px"
                height="10px"
                rounded="full"
                delayIndex={delay}
              />
              <span className="text-zinc-700 text-xs select-none">·</span>
              <SkeletonBase
                width="70px"
                height="10px"
                rounded="full"
                delayIndex={delay}
              />
            </div>

            {/* Event / Trace Title Line */}
            <SkeletonBase
              width={idx % 2 === 0 ? '78%' : '65%'}
              height="18px"
              rounded="md"
              delayIndex={delay}
              className="mb-4" /* Preserving SSC-07 key characteristic: larger spacing */
            />

            {/* Supporting Detail Lines */}
            <div className="space-y-2">
              <SkeletonBase
                width="92%"
                height="11px"
                rounded="full"
                delayIndex={delay}
              />
              <SkeletonBase
                width={idx % 2 === 0 ? '58%' : '72%'}
                height="11px"
                rounded="full"
                delayIndex={delay}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
};

/* =============================================================================
   2. CODEFRONTS SSC-09 — CONTENT / ANALYSIS CARD & CHART SKELETON
   Anatomy:
   - For Charts: Preserves the exact 400px–450px container geometry with axes,
     grid lines, and threshold markers. ZERO fake data curves.
   - For Analytical Cards: Metric readout placeholders + analytical summary blocks.
   ============================================================================= */

export interface AnalysisCardSkeletonProps {
  type?: 'chart' | 'card' | 'metrics';
  title?: string;
  className?: string;
  ariaLabel?: string;
}

export const AnalysisCardSkeleton: React.FC<AnalysisCardSkeletonProps> = ({
  type = 'chart',
  title = 'ANALYSIS / FORECAST',
  className = '',
  ariaLabel,
}) => {
  const effectiveAriaLabel = ariaLabel || `Loading ${title}...`;

  if (type === 'chart') {
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label={effectiveAriaLabel}
        className={`relative w-full h-[400px] sm:h-[450px] bg-[#08080A] border border-[#27272A]/70 rounded-3xl p-6 overflow-hidden select-none shadow-[0_4px_24px_rgba(0,0,0,0.4)] font-mono ${className}`}
      >
        <span className="sr-only">{effectiveAriaLabel}</span>

        {/* Chart Header Placeholder */}
        <div className="flex items-center justify-between mb-4 border-b border-white/5 pb-3">
          <div className="flex items-center gap-2">
            <SkeletonBase width="10px" height="10px" rounded="full" accent />
            <span className="text-[11px] font-semibold text-zinc-500 tracking-wider uppercase">{title}</span>
          </div>
          <div className="flex items-center gap-4">
            <SkeletonBase width="80px" height="10px" rounded="full" />
            <SkeletonBase width="90px" height="10px" rounded="full" />
          </div>
        </div>

        {/* Background Grid & Threshold Geometry (Pure non-data structural lines) */}
        <div className="absolute inset-x-6 top-20 bottom-14 flex flex-col justify-between pointer-events-none opacity-40">
          <div className="w-full border-b border-dashed border-zinc-700/60 flex items-center justify-between">
            <span className="text-[10px] text-zinc-600">PEAK CEILING 0.60</span>
          </div>
          <div className="w-full border-b border-dashed border-zinc-700/60 flex items-center justify-between">
            <span className="text-[10px] text-zinc-600">TARGET CEILING 0.40</span>
          </div>
          <div className="w-full border-b border-dashed border-zinc-800/60" />
          <div className="w-full border-b border-dashed border-zinc-800/60" />
        </div>

        {/* Center Muted Structural Zone with Shimmer (Non-data block) */}
        <div className="absolute inset-x-20 top-28 bottom-20 flex items-center justify-center pointer-events-none">
          <SkeletonBase
            width="65%"
            height="55%"
            rounded="2xl"
            className="opacity-25"
          />
        </div>

        {/* Y-axis placeholder labels */}
        <div className="absolute left-3 top-20 bottom-14 flex flex-col justify-between font-mono text-[11px] text-zinc-600 pointer-events-none select-none">
          <span>1.00</span>
          <span>0.80</span>
          <span>0.60</span>
          <span>0.40</span>
          <span>0.20</span>
          <span>0.00</span>
        </div>

        {/* X-axis placeholder labels */}
        <div className="absolute bottom-3 left-12 right-6 flex justify-between font-mono text-[11px] text-zinc-600 pt-2 border-t border-white/5 pointer-events-none select-none">
          <span>T−30s</span>
          <span>T−20s</span>
          <span>T−10s</span>
          <span className="text-zinc-400">T0 [PRESENT]</span>
          <span>+10s</span>
          <span>+20s</span>
          <span>+30s</span>
        </div>
      </div>
    );
  }

  if (type === 'metrics') {
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label={ariaLabel}
        className={`p-6 bg-[#08080A] border border-[#27272A]/60 rounded-3xl grid grid-cols-2 md:grid-cols-5 gap-6 font-mono shadow-[0_4px_24px_rgba(0,0,0,0.4)] ${className}`}
      >
        <span className="sr-only">{effectiveAriaLabel}</span>
        {Array.from({ length: 5 }).map((_, idx) => (
          <div key={idx} className="space-y-2">
            <SkeletonBase width="70%" height="10px" rounded="full" delayIndex={((idx % 5) + 1) as 1 | 2 | 3 | 4 | 5} />
            <SkeletonBase width="45%" height="28px" rounded="md" delayIndex={((idx % 5) + 1) as 1 | 2 | 3 | 4 | 5} />
          </div>
        ))}
      </div>
    );
  }

  // Generic Card
  return (
    <div
      role="status"
      aria-busy="true"
      aria-label={effectiveAriaLabel}
      className={`ssc-analysis-card border border-[#27272A]/70 bg-[#08080A] rounded-3xl p-6 font-mono space-y-4 shadow-[0_4px_24px_rgba(0,0,0,0.45)] ${className}`}
    >
      <span className="sr-only">{effectiveAriaLabel}</span>
      <div className="flex items-center justify-between border-b border-white/5 pb-3">
        <span className="text-[11px] font-semibold text-zinc-500 tracking-wider uppercase">{title}</span>
        <SkeletonBase width="60px" height="12px" rounded="full" />
      </div>
      <div className="space-y-2.5">
        <SkeletonBase width="90%" height="12px" rounded="full" />
        <SkeletonBase width="75%" height="12px" rounded="full" />
        <SkeletonBase width="40%" height="12px" rounded="full" />
      </div>
    </div>
  );
};

/* =============================================================================
   3. CODEFRONTS SSC-10 — FORM INPUT / APPROVAL GATE PLACEHOLDER
   Anatomy:
   - Status beacon badge labeled: "LOADING APPROVAL REQUEST"
   - Recommended action input block
   - Target, urgency, impact, and reversibility structured input rows
   - Textarea silhouette + muted action button placeholders
   - CRITICAL: Never mimics APPROVED, EXECUTED, or AUTHORIZED
   ============================================================================= */

export interface ApprovalFormSkeletonProps {
  className?: string;
  ariaLabel?: string;
}

export const ApprovalFormSkeleton: React.FC<ApprovalFormSkeletonProps> = ({
  className = '',
  ariaLabel = 'Loading approval request...',
}) => {
  return (
    <div
      role="status"
      aria-busy="true"
      aria-label={ariaLabel}
      className={`space-y-8 font-mono ${className}`}
    >
      <span className="sr-only">{ariaLabel}</span>

      {/* Status Badge: Explicitly indicates LOADING APPROVAL REQUEST */}
      <div className="flex items-center gap-4">
        <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full border border-white/10 bg-white/[0.02]">
          <SkeletonBase width={8} height={8} rounded="full" accent />
          <span className="text-zinc-500 text-xs font-semibold tracking-widest uppercase">
            LOADING APPROVAL REQUEST
          </span>
        </div>
        <SkeletonBase width="180px" height="12px" rounded="full" />
      </div>

      {/* Proposed Intervention Card Placeholder */}
      <div className="ssc-form-card border border-[#27272A]/70 bg-[#08080A] p-8 rounded-3xl shadow-[0_4px_24px_rgba(0,0,0,0.4)]">
        <div className="flex items-center justify-between border-b border-white/5 pb-4 mb-6">
          <SkeletonBase width="240px" height="12px" rounded="full" />
          <SkeletonBase width="100px" height="12px" rounded="full" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Action Details Placeholder */}
          <div className="space-y-5 lg:col-span-2">
            <SkeletonBase width="60%" height="32px" rounded="md" />
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <SkeletonBase width="50px" height="10px" rounded="full" />
                <SkeletonBase width="120px" height="16px" rounded="md" />
              </div>
              <div className="space-y-1.5">
                <SkeletonBase width="60px" height="10px" rounded="full" />
                <SkeletonBase width="80px" height="16px" rounded="md" />
              </div>
              <div className="space-y-1.5">
                <SkeletonBase width="90px" height="10px" rounded="full" />
                <SkeletonBase width="180px" height="14px" rounded="md" />
              </div>
              <div className="space-y-1.5">
                <SkeletonBase width="80px" height="10px" rounded="full" />
                <SkeletonBase width="140px" height="14px" rounded="md" />
              </div>
            </div>
          </div>

          {/* Contextual Evidence Panel Placeholder */}
          <div className="p-5 rounded-2xl bg-white/[0.02] border border-white/5 space-y-3">
            <SkeletonBase width="100px" height="10px" rounded="full" />
            <div className="space-y-2">
              <SkeletonBase width="100%" height="12px" rounded="full" />
              <SkeletonBase width="85%" height="12px" rounded="full" />
              <SkeletonBase width="65%" height="12px" rounded="full" />
            </div>
          </div>
        </div>
      </div>

      {/* Operator Action Area Placeholder */}
      <div className="border border-[#27272A]/70 bg-[#08080A] p-8 rounded-3xl shadow-[0_4px_24px_rgba(0,0,0,0.4)] space-y-5">
        <div className="space-y-1.5">
          <SkeletonBase width="180px" height="10px" rounded="full" />
          <SkeletonBase width="100%" height="64px" rounded="xl" />
        </div>

        {/* Muted Non-interactive Button Silhouettes */}
        <div className="flex items-center gap-4 pt-2">
          <SkeletonBase width="210px" height="42px" rounded="full" />
          <SkeletonBase width="150px" height="42px" rounded="full" />
        </div>
      </div>
    </div>
  );
};
