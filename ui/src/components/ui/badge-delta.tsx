import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"
import {
  RiArrowDownLine,
  RiArrowDownSFill,
  RiArrowRightLine,
  RiArrowRightSFill,
  RiArrowUpLine,
  RiArrowUpSFill,
} from "@remixicon/react"

export const badgeDeltaVariants = cva(
  "inline-flex items-center text-tremor-label font-semibold",
  {
    variants: {
      variant: {
        outline:
          "gap-x-1 rounded-tremor-small px-2 py-1 ring-1 ring-inset ring-border",
        solid: "gap-x-1 rounded-tremor-small px-2 py-1",
        solidOutline:
          "gap-x-1 rounded-tremor-small px-2 py-1 ring-1 ring-inset",
        complex:
          "space-x-2.5 rounded-tremor-default bg-tremor-background py-1 pl-2.5 pr-1 ring-1 ring-inset ring-gray-200 dark:ring-gray-800 dark:bg-dark-tremor-background",
      },
      deltaType: {
        increase: "",
        decrease: "",
        neutral: "",
      },
      iconStyle: {
        filled: "",
        line: "",
      },
    },
    compoundVariants: [
      // ── outline ──────────────────────────────────────────────────────────
      // Design system: increase = electric yellow (informational signal),
      // decrease = critical red (degradation/threat), neutral = muted grey.
      // Never green — green is a forbidden major accent per locked design system.
      {
        deltaType: "increase",
        variant: "outline",
        className: "text-[#FFD60A] ring-[#FFD60A]/30 bg-[#FFD60A]/10",
      },
      {
        deltaType: "decrease",
        variant: "outline",
        className: "text-[#FF304F] ring-[#FF304F]/30 bg-[#FF304F]/10",
      },
      {
        deltaType: "neutral",
        variant: "outline",
        className: "text-[#707070] ring-white/10 bg-white/[0.02]",
      },
      // ── solid ─────────────────────────────────────────────────────────────
      {
        deltaType: "increase",
        variant: "solid",
        className: "bg-[#FFD60A]/15 text-[#FFD60A]",
      },
      {
        deltaType: "decrease",
        variant: "solid",
        className: "bg-[#FF304F]/15 text-[#FF304F]",
      },
      {
        deltaType: "neutral",
        variant: "solid",
        className: "bg-white/[0.05] text-[#707070]",
      },
      // ── solidOutline ──────────────────────────────────────────────────────
      {
        deltaType: "increase",
        variant: "solidOutline",
        className: "bg-[#FFD60A]/10 text-[#FFD60A] ring-[#FFD60A]/25",
      },
      {
        deltaType: "decrease",
        variant: "solidOutline",
        className: "bg-[#FF304F]/10 text-[#FF304F] ring-[#FF304F]/25",
      },
      {
        deltaType: "neutral",
        variant: "solidOutline",
        className: "bg-white/[0.03] text-[#707070] ring-white/10",
      },
    ],
  },
)

export interface BadgeDeltaProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeDeltaVariants> {
  value: string | number
}

const DeltaIcon = ({
  deltaType,
  iconStyle,
}: {
  deltaType: "increase" | "decrease" | "neutral"
  iconStyle: "filled" | "line"
}) => {
  const icons = {
    increase: {
      filled: RiArrowUpSFill,
      line: RiArrowUpLine,
    },
    decrease: {
      filled: RiArrowDownSFill,
      line: RiArrowDownLine,
    },
    neutral: {
      filled: RiArrowRightSFill,
      line: RiArrowRightLine,
    },
  }

  const Icon = icons[deltaType][iconStyle]
  return <Icon className="-ml-0.5 size-4" aria-hidden={true} />
}

export function BadgeDelta({
  className,
  variant = "outline",
  deltaType = "neutral",
  iconStyle = "filled",
  value,
  ...props
}: BadgeDeltaProps) {
  const safeDeltaType = (deltaType ?? "neutral") as "increase" | "decrease" | "neutral";
  const safeIconStyle = (iconStyle ?? "filled") as "filled" | "line";

  if (variant === "complex") {
    return (
      <span
        className={cn(badgeDeltaVariants({ variant, className }))}
        {...props}
      >
        <span
          className={cn(
            "text-tremor-label font-semibold",
            deltaType === "increase" &&
              "text-[#FFD60A]",
            deltaType === "decrease" && "text-[#FF304F]",
            deltaType === "neutral" &&
              "text-[#707070]",
          )}
        >
          {value}
        </span>
        <span
          className={cn(
            "rounded-tremor-small px-2 py-1 text-tremor-label font-medium",
            deltaType === "increase" && "bg-[#FFD60A]/10 text-[#FFD60A]",
            deltaType === "decrease" && "bg-[#FF304F]/10 text-[#FF304F]",
            deltaType === "neutral" &&
              "bg-white/[0.03] text-[#707070]",
          )}
        >
          <DeltaIcon deltaType={safeDeltaType} iconStyle="line" />
        </span>
      </span>
    )
  }

  return (
    <span
      className={cn(badgeDeltaVariants({ variant, deltaType, className }))}
      {...props}
    >
      <DeltaIcon deltaType={safeDeltaType} iconStyle={safeIconStyle} />
      {value}
    </span>
  )
}
