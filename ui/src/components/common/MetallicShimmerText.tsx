import React from 'react';

/**
 * CodeFronts CTH-08 — Shimmer / Metallic Shine Effect
 *
 * Source of truth: CodeFronts CTH-08
 * Mechanism: 5-stop metallic gradient clipped into glyphs with a 250% background-size
 * and smooth background-position sweep (97% -> 3%) on hover/focus.
 *
 * Visual adaptations for SIH Predictive Defense:
 * - Adapted to #000001, #FFFFFF, and #F0C808 cyber gold palette (technical brushed foil).
 * - Typography preserved in Hanken Grotesk / JetBrains Mono.
 * - Reserved for identity and brand accents (never applied to live data or security states).
 */

export interface MetallicShimmerTextProps extends React.HTMLAttributes<HTMLElement> {
  children: React.ReactNode;
  as?: 'span' | 'h1' | 'h2' | 'h3' | 'p' | 'div' | 'b';
  variant?: 'gold' | 'monochrome' | 'silver';
  mode?: 'sweep' | 'ambient' | 'static';
  className?: string;
  'data-cursor'?: string;
}

export const MetallicShimmerText: React.FC<MetallicShimmerTextProps> = ({
  children,
  as: Component = 'span',
  variant = 'gold',
  mode = 'sweep',
  className = '',
  style,
  'data-cursor': dataCursor,
  ...rest
}) => {
  const variantClass =
    variant === 'gold'
      ? 'cth-shimmer--gold'
      : variant === 'silver'
      ? 'cth-shimmer--silver'
      : 'cth-shimmer--monochrome';

  const modeClass =
    mode === 'sweep'
      ? 'cth-shimmer--sweep'
      : mode === 'ambient'
      ? 'cth-shimmer--ambient'
      : '';

  const combinedClasses = `cth-shimmer ${variantClass} ${modeClass} ${className}`.trim();

  return React.createElement(
    Component,
    {
      className: combinedClasses,
      style,
      'data-cursor': dataCursor,
      tabIndex: rest.tabIndex ?? (mode === 'sweep' ? 0 : undefined),
      ...rest,
    },
    children
  );
};
