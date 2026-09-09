/**
 * @author: @kokonut-labs
 * @description: Slide Text Button with animated vertical text transition
 * @version: 1.0.0
 * @date: 2025-11-02
 * @license: MIT
 * @website: https://kokonutui.com
 * @github: https://github.com/kokonut-labs/kokonutui
 */

import { motion } from "motion/react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";

export interface SlideTextButtonProps
  extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  text?: string;
  hoverText?: string;
  href?: string;
  className?: string;
  variant?: "default" | "ghost";
}

export default function SlideTextButton({
  text = "ENTER COMMAND CENTER",
  hoverText,
  href = "/command-center",
  className,
  variant = "default",
  ...props
}: SlideTextButtonProps) {
  const slideText = hoverText ?? text;
  const variantStyles =
    variant === "ghost"
      ? "border border-[#27272A] text-white hover:bg-white/5 rounded-full"
      : "bg-[#F0C808] text-black hover:bg-[#FFE14C] shadow-[0_0_18px_rgba(240,200,8,0.35)] hover:shadow-[0_0_24px_rgba(240,200,8,0.55)] rounded-full";

  return (
    <motion.div
      animate={{ x: 0, opacity: 1, transition: { duration: 0.2 } }}
      className="relative"
      initial={{ x: 200, opacity: 0 }}
    >
      <Link
        className={cn(
          "group relative inline-flex h-12 items-center justify-center overflow-hidden rounded-full px-8 font-mono font-bold text-sm tracking-wider uppercase transition-all duration-300 md:min-w-64",
          variantStyles,
          className
        )}
        to={href}
        {...props}
      >
        <span className="relative inline-block transition-transform duration-300 ease-in-out group-hover:-translate-y-full">
          <span className="flex items-center gap-2 opacity-100 transition-opacity duration-300 group-hover:opacity-0">
            <span className="font-semibold">{text}</span>
          </span>
          <span className="absolute top-full left-0 flex items-center gap-2 opacity-0 transition-opacity duration-300 group-hover:opacity-100">
            <span className="font-semibold">{slideText}</span>
          </span>
        </span>
      </Link>
    </motion.div>
  );
}
