/**
 * @author: @dorianbaffier
 * @description: Mouse Effect Card - Interactive card with animated dot pattern that responds to mouse movement
 * @version: 1.0.0
 * @date: 2025-01-30
 * @license: MIT
 * @website: https://kokonutui.com
 * @github: https://github.com/kokonut-labs/kokonutui
 */

import { motion, useMotionValue, useSpring, useTransform } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const SPRING_CONFIG = { stiffness: 300, damping: 30, mass: 0.5 };
const OPACITY_DURATION_BASE = 0.8;
const OPACITY_DURATION_VARIATION = 0.2;
const OPACITY_EASE = [0.4, 0, 0.2, 1] as const;
const OPACITY_DELAY_CYCLE = 1.5;
const OPACITY_DELAY_STEP = 0.02;
const MIN_OPACITY_MULTIPLIER = 0.5;
const MAX_OPACITY_MULTIPLIER = 1.5;
const MIN_OPACITY_FALLBACK = 0.3;
const PROXIMITY_MULTIPLIER = 1.2;
const PROXIMITY_OPACITY_BOOST = 0.8;

export interface MouseEffectCardProps {
  className?: string;
  children?: React.ReactNode;
  dotSize?: number;
  dotSpacing?: number;
  repulsionRadius?: number;
  repulsionStrength?: number;
  title?: string;
  subtitle?: string;
  topText?: string;
  topSubtext?: string;
  primaryCtaText?: string;
  primaryCtaUrl?: string;
  secondaryCtaText?: string;
  secondaryCtaUrl?: string;
  footerText?: string;
  ariaLabel?: string;
}

interface Dot {
  id: string;
  x: number;
  y: number;
  baseX: number;
  baseY: number;
  opacity: number;
}

interface DotComponentProps {
  dot: Dot;
  index: number;
  dotSize: number;
  mouseX: ReturnType<typeof useMotionValue<number>>;
  mouseY: ReturnType<typeof useMotionValue<number>>;
  repulsionRadius: number;
  repulsionStrength: number;
}

function calculateDistance(
  x1: number,
  y1: number,
  x2: number,
  y2: number
): number {
  const dx = x1 - x2;
  const dy = y1 - y2;
  return Math.sqrt(dx * dx + dy * dy);
}

function generateDots(width: number, height: number, spacing: number): Dot[] {
  const dots: Dot[] = [];
  const cols = Math.ceil(width / spacing);
  const rows = Math.ceil(height / spacing);
  const centerX = width / 2;
  const centerY = height / 2;
  const maxDistance = Math.sqrt(centerX * centerX + centerY * centerY);

  for (let row = 0; row <= rows; row++) {
    for (let col = 0; col <= cols; col++) {
      const x = col * spacing;
      const y = row * spacing;

      // Calculate distance from center
      const dx = x - centerX;
      const dy = y - centerY;
      const distanceFromCenter = Math.sqrt(dx * dx + dy * dy);

      // Calculate edge factor (0 at edges, 1 at center)
      const edgeFactor = Math.min(distanceFromCenter / (maxDistance * 0.7), 1);

      // Skip dots near edges with probability based on distance
      if (Math.random() > edgeFactor) {
        continue;
      }

      const pattern = (row + col) % 3;
      const baseOpacities = [0.3, 0.5, 0.7];
      const opacity = baseOpacities[pattern] * edgeFactor;

      dots.push({
        id: `dot-${row}-${col}`,
        x,
        y,
        baseX: x,
        baseY: y,
        opacity,
      });
    }
  }

  return dots;
}

function DotComponent({
  dot,
  index,
  dotSize,
  mouseX,
  mouseY,
  repulsionRadius,
  repulsionStrength,
}: DotComponentProps) {
  const posX = useTransform([mouseX, mouseY], () => {
    const mx = mouseX.get();
    const my = mouseY.get();

    if (!(Number.isFinite(mx) && Number.isFinite(my))) {
      return 0;
    }

    const dx = dot.baseX - mx;
    const dy = dot.baseY - my;
    const distance = Math.sqrt(dx * dx + dy * dy);

    if (distance < repulsionRadius) {
      const force = (1 - distance / repulsionRadius) * repulsionStrength;
      const angle = Math.atan2(dy, dx);
      return Math.cos(angle) * force;
    }

    return 0;
  });

  const posY = useTransform([mouseX, mouseY], () => {
    const mx = mouseX.get();
    const my = mouseY.get();

    if (!(Number.isFinite(mx) && Number.isFinite(my))) {
      return 0;
    }

    const dx = dot.baseX - mx;
    const dy = dot.baseY - my;
    const distance = Math.sqrt(dx * dx + dy * dy);

    if (distance < repulsionRadius) {
      const force = (1 - distance / repulsionRadius) * repulsionStrength;
      const angle = Math.atan2(dy, dx);
      return Math.sin(angle) * force;
    }

    return 0;
  });

  const opacityBoost = useTransform([mouseX, mouseY], () => {
    const mx = mouseX.get();
    const my = mouseY.get();

    if (!(Number.isFinite(mx) && Number.isFinite(my))) return 0;

    const distance = calculateDistance(dot.baseX, dot.baseY, mx, my);
    const maxDistance = repulsionRadius * PROXIMITY_MULTIPLIER;

    if (distance < maxDistance) {
      const proximityFactor = 1 - distance / maxDistance;
      return proximityFactor * PROXIMITY_OPACITY_BOOST;
    }

    return 0;
  });

  const x = useSpring(posX, SPRING_CONFIG);
  const y = useSpring(posY, SPRING_CONFIG);

  const baseMinOpacity = Math.max(
    dot.opacity * MIN_OPACITY_MULTIPLIER,
    MIN_OPACITY_FALLBACK
  );
  const baseMaxOpacity = Math.min(dot.opacity * MAX_OPACITY_MULTIPLIER, 1);

  const minOpacityWithBoost = useTransform(opacityBoost, (boost) =>
    Math.min(baseMinOpacity + boost, 1)
  );

  const delay = (index * OPACITY_DELAY_STEP) % OPACITY_DELAY_CYCLE;

  return (
    <motion.div
      animate={{
        opacity: [baseMinOpacity, baseMaxOpacity, baseMinOpacity],
      }}
      className="absolute rounded-full bg-zinc-600 will-change-transform dark:bg-zinc-600 pointer-events-none"
      initial={{ opacity: baseMinOpacity }}
      style={{
        width: dotSize,
        height: dotSize,
        left: dot.baseX,
        top: dot.baseY,
        x,
        y,
        opacity: useSpring(minOpacityWithBoost, {
          stiffness: 150,
          damping: 25,
        }),
      }}
      transition={{
        opacity: {
          duration:
            OPACITY_DURATION_BASE + (index % 4) * OPACITY_DURATION_VARIATION,
          repeat: Number.POSITIVE_INFINITY,
          ease: OPACITY_EASE,
          delay,
          times: [0, 0.5, 1],
        },
      }}
    />
  );
}

export function MouseEffectCard({
  className,
  children,
  dotSize = 2,
  dotSpacing = 16,
  repulsionRadius = 80,
  repulsionStrength = 20,
  title,
  subtitle,
  topText,
  topSubtext,
  primaryCtaText,
  primaryCtaUrl = "#",
  secondaryCtaText,
  secondaryCtaUrl = "#",
  footerText,
  ariaLabel,
}: MouseEffectCardProps) {
  const innerContainerRef = useRef<HTMLDivElement>(null);
  const mouseX = useMotionValue(Number.POSITIVE_INFINITY);
  const mouseY = useMotionValue(Number.POSITIVE_INFINITY);
  const [dots, setDots] = useState<Dot[]>([]);

  useEffect(() => {
    const updateDots = () => {
      if (!innerContainerRef.current) return;
      const rect = innerContainerRef.current.getBoundingClientRect();
      const newDots = generateDots(rect.width, rect.height, dotSpacing);
      setDots(newDots);
    };

    updateDots();

    const resizeObserver = new ResizeObserver(updateDots);
    if (innerContainerRef.current) {
      resizeObserver.observe(innerContainerRef.current);
    }

    return () => {
      resizeObserver.disconnect();
    };
  }, [dotSpacing]);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!innerContainerRef.current) return;

    const rect = innerContainerRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    mouseX.set(x);
    mouseY.set(y);
  };

  const handleMouseLeave = () => {
    mouseX.set(Number.POSITIVE_INFINITY);
    mouseY.set(Number.POSITIVE_INFINITY);
  };

  const handleFocus = () => {
    if (!innerContainerRef.current) return;
    const rect = innerContainerRef.current.getBoundingClientRect();
    mouseX.set(rect.width / 2);
    mouseY.set(rect.height / 2);
  };

  const handleBlur = () => {
    mouseX.set(Number.POSITIVE_INFINITY);
    mouseY.set(Number.POSITIVE_INFINITY);
  };

  return (
    <Card
      className={cn(
        "relative w-full overflow-hidden rounded-none border border-[#2a2a2a] bg-[#000000] p-0 shadow-none",
        className
      )}
    >
      <CardContent
        aria-label={ariaLabel ?? (title ? `${title} — ${subtitle ?? ''}` : 'Card')}
        className="relative w-full overflow-hidden p-0"
        onBlur={handleBlur}
        onFocus={handleFocus}
        onMouseLeave={handleMouseLeave}
        onMouseMove={handleMouseMove}
        ref={innerContainerRef}
        tabIndex={0}
      >
        {dots.map((dot, index) => (
          <DotComponent
            dot={dot}
            dotSize={dotSize}
            index={index}
            key={dot.id}
            mouseX={mouseX}
            mouseY={mouseY}
            repulsionRadius={repulsionRadius}
            repulsionStrength={repulsionStrength}
          />
        ))}

        {topText && (
          <div className="absolute top-4 left-4 z-10">
            <div className="relative flex flex-col gap-0.5">
              <p className="font-mono text-xs text-white uppercase tracking-widest">
                {topText}
              </p>
              {topSubtext && (
                <p className="font-mono text-[10px] text-[#707070]">
                  {topSubtext}
                </p>
              )}
            </div>
          </div>
        )}

        {children ? (
          <div className="relative z-10 h-full w-full">{children}</div>
        ) : (
          <div className="relative z-10 flex h-full flex-col items-center justify-center p-6">
            <div className="flex flex-col items-center gap-4">
              {title && (
                <h2 className="text-center font-bold text-2xl text-white tracking-tight">
                  {title}
                </h2>
              )}
              {subtitle && (
                <p className="max-w-sm text-center font-medium text-sm text-[#707070] leading-relaxed">
                  {subtitle}
                </p>
              )}
              {(primaryCtaText || secondaryCtaText) && (
                <div className="mt-2 flex items-center gap-3">
                  {primaryCtaText && (
                    <Button asChild className="rounded bg-[#FFD60A] text-black hover:bg-[#FFD60A]/90 font-mono text-xs" size="sm">
                      <a href={primaryCtaUrl}>{primaryCtaText}</a>
                    </Button>
                  )}
                  {secondaryCtaText && (
                    <Button asChild className="rounded border border-white/20 text-white hover:bg-white/5 font-mono text-xs" size="sm" variant="outline">
                      <a href={secondaryCtaUrl}>{secondaryCtaText}</a>
                    </Button>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {footerText && (
          <div className="absolute right-0 bottom-3 left-0 z-10 flex justify-center">
            <p className="font-mono text-[10px] text-[#707070]">
              {footerText}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export const LiquidGlassCard = MouseEffectCard;
export const LiquidButton = Button;
export default MouseEffectCard;
