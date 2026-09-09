import React, { useEffect, useState, useRef } from 'react';

/**
 * CodeFronts GLZ-11 — KPI Numerical Count-Up
 *
 * Source: CodeFronts GLZ-11
 * Purpose: Smooth numerical increment for non-critical integer quantities
 * (e.g. flow count, packet count, event count, audit record count).
 *
 * Safety & Accessibility Constraints:
 * - DO NOT animate safety-critical risk scores or approval states.
 * - Screen readers immediately receive the true final value.
 * - Respects prefers-reduced-motion (snaps immediately).
 * - Avoids layout shift via tabular-nums monospace typography.
 */

export interface GlassKpiCountUpProps extends React.HTMLAttributes<HTMLSpanElement> {
  value: number;
  duration?: number; // ms, default 650
  formatFn?: (val: number) => string;
}

export const GlassKpiCountUp: React.FC<GlassKpiCountUpProps> = ({
  value,
  duration = 650,
  formatFn,
  className = '',
  ...rest
}) => {
  const [displayValue, setDisplayValue] = useState<number>(value);
  const prevValueRef = useRef<number>(value);
  const animFrameRef = useRef<number | null>(null);

  useEffect(() => {
    // Check for reduced motion preference
    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReducedMotion || duration <= 0) {
      setDisplayValue(value);
      prevValueRef.current = value;
      return;
    }

    const startValue = prevValueRef.current;
    const endValue = value;
    const diff = endValue - startValue;

    if (diff === 0) {
      setDisplayValue(value);
      return;
    }

    const startTime = performance.now();

    const updateCount = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);

      // Smooth ease-out cubic curve
      const easeOut = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(startValue + diff * easeOut);

      setDisplayValue(current);

      if (progress < 1) {
        animFrameRef.current = requestAnimationFrame(updateCount);
      } else {
        setDisplayValue(endValue);
        prevValueRef.current = endValue;
      }
    };

    animFrameRef.current = requestAnimationFrame(updateCount);

    return () => {
      if (animFrameRef.current) {
        cancelAnimationFrame(animFrameRef.current);
      }
    };
  }, [value, duration]);

  const formatted = formatFn ? formatFn(displayValue) : displayValue.toLocaleString();
  const screenReaderText = formatFn ? formatFn(value) : value.toLocaleString();

  return (
    <span
      className={`tabular-nums font-mono ${className}`.trim()}
      aria-label={screenReaderText}
      {...rest}
    >
      {formatted}
    </span>
  );
};
