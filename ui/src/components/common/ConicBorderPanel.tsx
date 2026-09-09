import React from 'react';

/**
 * CodeFronts AC-18 — Animated Conic Gradient Border Card (Conic Rotate)
 *
 * Source of truth: CodeFronts AC-18
 * Mechanism: CSS @property --ac18-angle with hardware-composited conic-gradient
 * and masked-ring border technique.
 *
 * Visual Adaptations for SIH Predictive Defense:
 * - Pure industrial monochrome and signal gold palette (#FFFFFF, #A1A1AA, #F0C808, #3F3F46, transparent).
 * - Restrained "comet trail" highlight occupying only a portion of the border perimeter.
 * - Semantic UI states: 'active', 'decision', 'approval', 'live', and 'static'.
 * - Non-animated, stable buttons and controls (APPROVE / REJECT controls remain rock-solid).
 * - Zero pointer event interception (pointer-events: none on decorative layers).
 * - Reduced motion support via @media (prefers-reduced-motion: reduce).
 */

export type ConicBorderVariant = 'active' | 'decision' | 'approval' | 'live' | 'static';

export interface ConicBorderPanelProps extends React.HTMLAttributes<HTMLDivElement> {
  /**
   * Semantic state indicator:
   * - 'active': Active predictive intelligence (AR(5) forecast horizon, ~6s revolution).
   * - 'decision': Recommended intervention (MSI candidate review, ~4.5s revolution).
   * - 'approval': Operator action required (Pending human gate, ~3.8s revolution).
   * - 'live': Connected telemetry activity indicator (~6.5s revolution).
   * - 'static': Clean static card, zero rotation, zero bloom (default).
   */
  variant?: ConicBorderVariant;

  /**
   * Controls whether rotation animation is active.
   * When false, reverts to static idle state. Default: true.
   */
  animated?: boolean;

  /**
   * Whether to allow subtle edge bloom. Default: true.
   */
  bloom?: boolean;

  /**
   * HTML tag / wrapper component to render. Default: 'div'.
   */
  as?: React.ElementType;

  /**
   * Additional classes for the outer panel container.
   */
  className?: string;

  /**
   * Optional wrapper classes for inner content.
   */
  innerClassName?: string;

  children: React.ReactNode;
}

export const ConicBorderPanel = React.forwardRef<HTMLDivElement, ConicBorderPanelProps>(
  (
    {
      variant = 'static',
      animated = true,
      bloom = true,
      as: Component = 'div',
      className = '',
      innerClassName = '',
      children,
      style,
      ...rest
    },
    ref
  ) => {
    // Only animate if explicit opt-in and not in static variant
    const borderState = animated && variant !== 'static' ? variant : 'idle';

    return (
      <Component
        ref={ref}
        className={`ac18-conic-panel ${className}`.trim()}
        data-border-state={borderState}
        data-bloom={bloom ? 'true' : 'false'}
        style={style}
        {...rest}
      >
        {innerClassName ? (
          <div className={innerClassName}>{children}</div>
        ) : (
          children
        )}
      </Component>
    );
  }
);

ConicBorderPanel.displayName = 'ConicBorderPanel';
