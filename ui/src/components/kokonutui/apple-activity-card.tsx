/**
 * @author: @kokonutui
 * @description: Apple Activity Card
 * @version: 1.0.0
 * @date: 2025-06-26
 * @license: MIT
 * @website: https://kokonutui.com
 * @github: https://github.com/kokonut-labs/kokonutui
 */

import { motion } from "motion/react";
import { cn } from "@/lib/utils";

export interface ActivityData {
  label: string;
  value: number;
  color: string;
  size: number;
  current: number | string;
  target: number | string;
  unit: string;
}

interface CircleProgressProps {
  data: ActivityData;
  index: number;
}

export const DEFAULT_SECURITY_ACTIVITIES: ActivityData[] = [
  {
    label: "RISK",
    value: 83,
    color: "#FFD60A",
    size: 200,
    current: 0.83,
    target: 1.0,
    unit: "HIGH",
  },
  {
    label: "TRUST",
    value: 72,
    color: "#FFFFFF",
    size: 160,
    current: 0.72,
    target: 1.0,
    unit: "EXP",
  },
  {
    label: "CONFIDENCE",
    value: 74,
    color: "#707070",
    size: 120,
    current: 74,
    target: 100,
    unit: "%",
  },
];

const CircleProgress = ({ data, index }: CircleProgressProps) => {
  const strokeWidth = 16;
  const radius = (data.size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const progress = ((100 - data.value) / 100) * circumference;

  const gradientId = `gradient-${data.label.toLowerCase().replace(/[^a-z0-9]/g, "-")}`;
  const gradientUrl = `url(#${gradientId})`;

  return (
    <motion.div
      animate={{ opacity: 1, scale: 1 }}
      className="absolute inset-0 flex items-center justify-center"
      initial={{ opacity: 0, scale: 0.8 }}
      transition={{ duration: 0.8, delay: index * 0.2, ease: "easeOut" }}
    >
      <div className="relative">
        <svg
          aria-label={`${data.label} Activity Progress - ${data.value}%`}
          className="-rotate-90 transform"
          height={data.size}
          viewBox={`0 0 ${data.size} ${data.size}`}
          width={data.size}
        >
          <title>{`${data.label} Activity Progress - ${data.value}%`}</title>

          <defs>
            <linearGradient id={gradientId} x1="0%" x2="100%" y1="0%" y2="100%">
              <stop
                offset="0%"
                style={{
                  stopColor: data.color,
                  stopOpacity: 1,
                }}
              />
              <stop
                offset="100%"
                style={{
                  stopColor:
                    data.color === "#FFD60A"
                      ? "#FFE866"
                      : data.color === "#FFFFFF"
                        ? "#D4D4D8"
                        : "#A1A1AA",
                  stopOpacity: 1,
                }}
              />
            </linearGradient>
          </defs>

          <circle
            className="text-zinc-800/40"
            cx={data.size / 2}
            cy={data.size / 2}
            fill="none"
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
          />

          <motion.circle
            animate={{ strokeDashoffset: progress }}
            cx={data.size / 2}
            cy={data.size / 2}
            fill="none"
            initial={{ strokeDashoffset: circumference }}
            r={radius}
            stroke={gradientUrl}
            strokeDasharray={circumference}
            strokeLinecap="round"
            strokeWidth={strokeWidth}
            style={{
              filter: "drop-shadow(0 0 6px rgba(0,0,0,0.15))",
            }}
            transition={{
              duration: 1.8,
              delay: index * 0.2,
              ease: "easeInOut",
            }}
          />
        </svg>
      </div>
    </motion.div>
  );
};

const DetailedActivityInfo = ({ activities }: { activities: ActivityData[] }) => {
  return (
    <motion.div
      animate={{ opacity: 1, x: 0 }}
      className="ml-6 sm:ml-12 flex flex-col gap-6 sm:gap-8"
      initial={{ opacity: 0, x: 20 }}
      transition={{ duration: 0.5, delay: 0.3 }}
    >
      {activities.map((activity) => (
        <motion.div className="flex flex-col" key={activity.label}>
          <span
            className="text-[11px] tracking-[0.25em] uppercase text-[#707070] mb-1 font-medium"
            style={{ fontFamily: 'var(--font-mono)' }}
          >
            {activity.label}
          </span>
          <span
            className="font-bold text-3xl sm:text-5xl tracking-tight leading-none"
            style={{ color: activity.color, fontFamily: 'var(--font-display)' }}
          >
            {activity.current}
            <span
              className="ml-2.5 text-xs text-[#707070] font-normal tracking-wider"
              style={{ fontFamily: 'var(--font-mono)' }}
            >
              / {activity.target} {activity.unit}
            </span>
          </span>
        </motion.div>
      ))}
    </motion.div>
  );
};

export default function AppleActivityCard({
  title,
  activities = DEFAULT_SECURITY_ACTIVITIES,
  className,
}: {
  title?: string;
  activities?: ActivityData[];
  className?: string;
}) {
  return (
    <div
      className={cn(
        "relative mx-auto w-full p-4 sm:p-6",
        "text-white",
        className
      )}
    >
      <div className="flex flex-col items-center gap-6">
        {title && (
          <motion.h2
            animate={{ opacity: 1, y: 0 }}
            className="font-mono text-xs tracking-widest text-[#707070] uppercase"
            initial={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.5 }}
          >
            {title}
          </motion.h2>
        )}

        <div className="flex flex-col sm:flex-row items-center justify-center gap-8 sm:gap-14">
          <div
            className="relative flex-shrink-0"
            style={{
              width: Math.max(...activities.map((a) => a.size)),
              height: Math.max(...activities.map((a) => a.size)),
            }}
          >
            {activities.map((activity, index) => (
              <CircleProgress
                data={activity}
                index={index}
                key={activity.label}
              />
            ))}
          </div>
          <DetailedActivityInfo activities={activities} />
        </div>
      </div>
    </div>
  );
}
