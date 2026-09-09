import React from 'react';

/**
 * CodeFronts GLZ-23 — Dark Glass Material Panel
 *
 * Source: CodeFronts GLZ-23
 * Core principles:
 * - Translucent dark fill: rgba(10, 10, 14, 0.72)
 * - Hardware-accelerated backdrop blur: 18px
 * - Restrained white border boundary: rgba(255, 255, 255, 0.08)
 * - Inset highlight: inset 0 1px 0 rgba(255, 255, 255, 0.10)
 * - Strict industrial monochrome cybersecurity palette (#000001, #080808, #FFFFFF)
 * - Fallback for browsers without backdrop-filter
 */

export type GlassVariant = 'default' | 'subtle' | 'bordered' | 'none';

export interface GlassPanelProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: GlassVariant;
  as?: React.ElementType;
  rounded?: string; // Tailwind rounded class, defaults to 'rounded-3xl'
  children: React.ReactNode;
}

export const GlassPanel = React.forwardRef<HTMLDivElement, GlassPanelProps>(
  (
    {
      variant = 'default',
      as: Component = 'div',
      rounded = 'rounded-3xl',
      className = '',
      children,
      ...rest
    },
    ref
  ) => {
    let glassClass = '';
    if (variant === 'default') {
      glassClass = 'glz-dark-glass';
    } else if (variant === 'subtle') {
      glassClass = 'glz-dark-glass-subtle';
    } else if (variant === 'bordered') {
      glassClass = 'glz-dark-glass-bordered';
    }

    return (
      <Component
        ref={ref}
        className={`${glassClass} ${rounded} ${className}`.trim()}
        {...rest}
      >
        {children}
      </Component>
    );
  }
);

GlassPanel.displayName = 'GlassPanel';
