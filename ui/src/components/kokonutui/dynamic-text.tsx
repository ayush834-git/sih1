/**
 * @author: @dorianbaffier
 * @description: Dynamic Text - Real system state transition indicator
 * @version: 1.0.0
 * @date: 2025-06-26
 * @license: MIT
 * @website: https://kokonutui.com
 * @github: https://github.com/kokonut-labs/kokonutui
 */

import { AnimatePresence, motion } from "motion/react";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

export interface StateStep {
  text: string;
  category?: string;
}

export const DEFAULT_STATE_STEPS: StateStep[] = [
  { text: "OBSERVE", category: "TELEMETRY" },
  { text: "PREDICT", category: "AR(5) INFERENCE" },
  { text: "RECONSIDER", category: "BOUNDED RISK" },
];

export interface DynamicTextProps {
  steps?: StateStep[];
  className?: string;
  onComplete?: () => void;
  loop?: boolean;
}

const DynamicText = ({
  steps = DEFAULT_STATE_STEPS,
  className,
  onComplete,
  loop = false,
}: DynamicTextProps) => {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isAnimating, setIsAnimating] = useState(true);

  useEffect(() => {
    if (!isAnimating) return;

    const interval = setInterval(() => {
      setCurrentIndex((prevIndex) => {
        const nextIndex = prevIndex + 1;

        if (nextIndex >= steps.length) {
          if (loop) {
            return 0;
          }
          clearInterval(interval);
          setIsAnimating(false);
          onComplete?.();
          return prevIndex;
        }

        return nextIndex;
      });
    }, 1200);

    return () => clearInterval(interval);
  }, [isAnimating, steps.length, loop, onComplete]);

  // Animation variants for the text
  const textVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: { y: 0, opacity: 1 },
    exit: { y: -100, opacity: 0 },
  };

  const currentStep = steps[currentIndex] || steps[0];

  return (
    <div
      aria-label="System state transition indicator"
      className={cn("flex items-center justify-center p-2 font-mono", className)}
    >
      <div className="relative flex h-10 w-full min-w-[240px] items-center justify-center overflow-visible">
        {isAnimating ? (
          <AnimatePresence mode="popLayout">
            <motion.div
              animate={textVariants.visible}
              aria-live="off"
              className="absolute flex items-center gap-2.5 font-mono text-sm tracking-widest text-[#FFD60A] uppercase"
              exit={textVariants.exit}
              initial={textVariants.hidden}
              key={currentIndex}
              transition={{ duration: 0.2, ease: "easeOut" }}
            >
              <div
                aria-hidden="true"
                className="h-2 w-2 rounded-full bg-[#FFD60A]"
              />
              <span className="font-bold">{currentStep.text}</span>
              {currentStep.category && (
                <span className="text-[10px] text-[#707070] border border-white/10 px-1.5 py-0.5 rounded">
                  {currentStep.category}
                </span>
              )}
            </motion.div>
          </AnimatePresence>
        ) : (
          <div className="flex items-center gap-2.5 font-mono text-sm tracking-widest text-[#FFD60A] uppercase">
            <div
              aria-hidden="true"
              className="h-2 w-2 rounded-full bg-[#FFD60A]"
            />
            <span className="font-bold">{currentStep.text}</span>
            {currentStep.category && (
              <span className="text-[10px] text-[#707070] border border-white/10 px-1.5 py-0.5 rounded">
                {currentStep.category}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default DynamicText;
